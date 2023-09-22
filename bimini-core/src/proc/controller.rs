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

        signal::pthread_sigmask(
            signal::SigmaskHow::SIG_SETMASK,
            Some(signal_config.source_signals()),
            None,
        )?;

        loop {
            match signal_config.parent_signals().wait() {
                Ok(signal::SIGCHLD) => {
                    tracing::info!("Received SIGCHILD due to exit, ignoring.")
                }

                Ok(signal::SIGUSR1) => {
                    tracing::info!(
                        "Received signal SIGUSR1, terminating signal event forwarding loop."
                    );
                    return Ok(());
                }

                Ok(signal) => {
                    tracing::info!("Passing signal to child: {signal}");
                    signal::kill(child_pid, signal).map_err(|eno| {
                        if eno == errno::Errno::ESRCH {
                            tracing::warn!("Child was dead when forwarding signal");
                        }
                        eno
                    })?;
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
                        "Controller child process {pid} exited normally with status {status}."
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
            if rc != -1 {
                if let Some(signal_forwarder) = self.signal_forwarder {
                    signal::kill(unistd::Pid::from_raw(0), signal::SIGUSR1)?;
                    signal_forwarder.join()??;
                }
                return Ok(ExitCode::from(TryInto::<u8>::try_into(rc)?));
            }
        }
    }
}
