use crate::error::BiminiResult;
use nix::{errno, sys::signal};

#[derive(Debug, Clone)]
pub struct SignalConfig {
    mask_set: signal::SigSet,
    source_set: signal::SigSet,
    sigttin_action: signal::SigAction,
    sigttou_action: signal::SigAction,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self::new(&[
            // Un-blockable signals
            signal::SIGKILL,
            signal::SIGSTOP,
            // Program signals
            signal::SIGABRT,
            signal::SIGBUS,
            #[cfg(not(target_os = "linux"))]
            signal::SIGEMT,
            signal::SIGFPE,
            signal::SIGILL,
            signal::SIGIOT,
            signal::SIGSEGV,
            signal::SIGSYS,
            signal::SIGTRAP,
        ])
    }
}

impl SignalConfig {
    pub fn new(protected_signals: &[signal::Signal]) -> Self {
        let mut mask = signal::SigSet::all();
        for sig in protected_signals {
            mask.remove(*sig);
        }

        let ignore_action = signal::SigAction::new(
            signal::SigHandler::SigIgn,
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );

        Self {
            mask_set: mask,
            source_set: signal::SigSet::empty(),
            sigttin_action: ignore_action,
            sigttou_action: ignore_action,
        }
    }

    pub fn mask(&mut self) -> BiminiResult<&mut Self> {
        signal::pthread_sigmask(
            signal::SigmaskHow::SIG_SETMASK,
            Some(&self.mask_set),
            Some(&mut self.source_set),
        )?;

        unsafe {
            self.sigttin_action = signal::sigaction(signal::SIGTTIN, &self.sigttin_action)?;
            self.sigttou_action = signal::sigaction(signal::SIGTTOU, &self.sigttou_action)?;
        }

        Ok(self)
    }

    pub fn unmask(&mut self) -> BiminiResult<&mut Self> {
        signal::pthread_sigmask(
            signal::SigmaskHow::SIG_SETMASK,
            Some(&self.source_set),
            None,
        )?;

        unsafe {
            signal::sigaction(signal::SIGTTIN, &self.sigttin_action)?;
            signal::sigaction(signal::SIGTTOU, &self.sigttou_action)?;
        }

        Ok(self)
    }

    pub fn mask_wait(&self) -> Result<signal::Signal, errno::Errno> {
        self.mask_set.wait()
    }

    pub fn source_wait(&self) -> Result<signal::Signal, errno::Errno> {
        self.source_set.wait()
    }
}
