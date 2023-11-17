use crate::{
    error::{BiminiError, BiminiResult},
    nix::SignalConfig,
    proc::ChildBuilder,
};
use nix::{
    errno,
    sys::{signal, wait},
    unistd,
};
use std::{process::ExitCode, thread};

#[derive(Debug, Default)]
pub struct Controller {
    signal_config: SignalConfig,
    child_pid: Option<unistd::Pid>,
    signal_forwarder: Option<std::thread::JoinHandle<BiminiResult<()>>>,
}

impl Controller {
    #[tracing::instrument(skip_all)]
    pub fn mask_signals(mut self) -> BiminiResult<Self> {
        tracing::info!("Masking proc signals.");
        self.signal_config.mask()?;
        Ok(self)
    }

    #[tracing::instrument(skip_all)]
    pub fn spawn(mut self, child_builder: ChildBuilder) -> BiminiResult<Self> {
        tracing::info!("Forking to spawn child process.");

        match unsafe { unistd::fork() } {
            Ok(unistd::ForkResult::Child) => {
                child_builder
                    .signal_config(&mut self.signal_config)
                    .build()?
                    .spawn()?;

                Ok(self)
            }

            Ok(unistd::ForkResult::Parent { child }) => {
                tracing::info!("Spawning child proc with pid {child}");
                self.child_pid = Some(child);
                Ok(self)
            }

            Err(errno) => {
                tracing::error!("Controller fork failed: {}", errno.desc());
                Err(errno.into())
            }
        }
    }

    #[tracing::instrument(skip_all)]
    fn signal_forwarder(signal_config: SignalConfig, child_pid: unistd::Pid) -> BiminiResult<()> {
        tracing::info!("Starting signal forwarding event loop");

        loop {
            let signal = signal_config.mask_wait();

            tracing::info!("Received Signal({signal:?}), dispatching");

            match signal {
                Ok(signal::Signal::SIGCHLD) => {
                    tracing::info!("Suppressing Signal(SIGCHLD)");
                }

                Ok(signal::Signal::SIGUSR1) => {
                    tracing::info!("Terminating signal_forwarder loop.");
                    return Ok(());
                }

                Ok(signal) => {
                    tracing::info!("Passing Signal({signal}) to Child(pid={child_pid})");

                    if let Err(errno) = signal::kill(child_pid, signal) {
                        match errno {
                            errno::Errno::ESRCH => tracing::warn!(
                                "Child(pid={child_pid}) was dead when forwarding, Signal({signal}) dropped."
                            ),
                            errno => {
                                tracing::error!("Received un-handled error passing signal to child: {errno}");
                                return Err(BiminiError::Errno(errno))
                            },
                        }
                    }
                }

                Err(errno @ errno::Errno::EAGAIN | errno @ errno::Errno::EINTR) => {
                    tracing::info!("Ignoring expected error: {}", errno.desc());
                }

                Err(errno) => {
                    tracing::error!("Unexpected error in sigwait: {}", errno.desc());
                    return Err(errno.into());
                }
            }
        }
    }

    #[tracing::instrument(skip_all)]
    pub fn start_signal_forwarder(mut self) -> BiminiResult<Self> {
        tracing::trace!("Spawning signal forwarder event loop thread.");

        if self.child_pid.is_none() {
            return Err(BiminiError::ProcController(
                "Signal forwarding requires a running child proc".to_string(),
            ));
        }

        let signal_config = self.signal_config.clone();
        let child_pid = self.child_pid.unwrap();

        self.signal_forwarder = Some(thread::spawn(move || {
            Controller::signal_forwarder(signal_config, child_pid)
        }));

        Ok(self)
    }

    #[tracing::instrument(skip_all)]
    pub fn reap_zombies(&self) -> BiminiResult<i32> {
        if self.child_pid.is_none() {
            return Err(BiminiError::ProcController(
                "Reaping zombies requires a running child proc".to_string(),
            ));
        }

        tracing::debug!("Reaping zombie processes.");

        let any_proc = unistd::Pid::from_raw(-1);
        let mut child_exitcode = -1;
        let child_pid = self.child_pid.unwrap();

        loop {
            match wait::waitpid(any_proc, None) {
                Ok(wait::WaitStatus::Exited(pid, status)) if pid == child_pid => {
                    tracing::info!(
                        "Controller child process Child(pid={pid}) exited normally with status {status}."
                    );
                    child_exitcode = status;
                }

                Ok(wait::WaitStatus::Exited(pid, status)) => {
                    tracing::info!("Zombie process with pid {pid} reaped with status {status}");
                }

                Ok(wait::WaitStatus::Signaled(pid, signal, _)) if pid == child_pid => {
                    tracing::info!("Controller child process {pid} exited with signal {signal}.");
                    child_exitcode = 128 + signal as i32;
                }

                Ok(wait::WaitStatus::Signaled(pid, signal, _)) => {
                    tracing::info!("Zombie process with pid {pid} reaped with signal {signal}.");
                }

                Ok(wait::WaitStatus::Stopped(pid, signal)) => {
                    tracing::info!("Controller process {pid} stopped with signal {signal}.");
                }

                Ok(wait::WaitStatus::Continued(pid)) => {
                    tracing::info!("Controller process {pid} continued.");
                }

                Ok(wait::WaitStatus::StillAlive) => {
                    tracing::debug!("No child to reap.");
                    break;
                }

                #[cfg(target_os = "linux")]
                Ok(wait::WaitStatus::PtraceEvent(pid, signal, status)) => {
                    tracing::info!(
                        "Controller process {pid} stopped via {signal} with ptrace event {status}."
                    );
                }

                #[cfg(target_os = "linux")]
                Ok(wait::WaitStatus::PtraceSyscall(pid)) => {
                    tracing::info!("Controller process {pid} stopped with PTRACE_O_TRACESYSGOOD.");
                }

                Err(nix::Error::ECHILD) => {
                    tracing::debug!("No child to wait.");
                    break;
                }

                Err(errno) => {
                    tracing::error!("Error while waiting for pids: {}", errno.desc());
                    return Err(BiminiError::Errno(errno));
                }
            }
        }

        Ok(child_exitcode)
    }

    #[tracing::instrument(skip_all)]
    pub fn run_reaper(self) -> BiminiResult<ExitCode> {
        loop {
            tracing::debug!("Running zombie reaper loop.");
            let rc = self.reap_zombies()?;

            if rc == -1 {
                continue;
            }

            tracing::trace!("Received child status code: {rc}. Cleaning up");
            if let Some(signal_forwarder) = self.signal_forwarder {
                tracing::trace!("Sending termination signal to signal_forwarding thread");
                signal::kill(unistd::getpid(), signal::SIGUSR1)?;

                tracing::trace!("Joining signal_forwarding thread");
                signal_forwarder.join()??;
            }

            return Ok(ExitCode::from(TryInto::<u8>::try_into(rc)?));
        }
    }
}
