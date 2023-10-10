use nix::sys::signal;

use crate::error::BiminiResult;

#[derive(Clone, Debug)]
pub struct SignalConfig {
    parent_signals: signal::SigSet,
    source_signals: signal::SigSet,
    sigttin_action: signal::SigAction,
    sigttou_action: signal::SigAction,
}

impl SignalConfig {
    pub fn parent_signals(&self) -> &signal::SigSet {
        &self.parent_signals
    }

    pub fn source_signals(&self) -> &signal::SigSet {
        &self.source_signals
    }

    pub fn sigttin_action(&self) -> &signal::SigAction {
        &self.sigttin_action
    }

    pub fn sigttou_action(&self) -> &signal::SigAction {
        &self.sigttou_action
    }

    pub fn new(protected_signals: Vec<signal::Signal>) -> Self {
        let mut parent_signals = signal::SigSet::all();
        for signal in protected_signals {
            parent_signals.remove(signal)
        }

        let ignore_action = signal::SigAction::new(
            signal::SigHandler::SigIgn,
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );

        SignalConfig {
            parent_signals,
            source_signals: signal::SigSet::empty(),
            sigttin_action: ignore_action,
            sigttou_action: ignore_action,
        }
    }

    pub fn mask(&mut self) -> BiminiResult<()> {
        signal::sigprocmask(
            signal::SigmaskHow::SIG_SETMASK,
            Some(&self.parent_signals),
            Some(&mut self.source_signals),
        )?;

        unsafe {
            self.sigttin_action = signal::sigaction(signal::SIGTTIN, &self.sigttin_action)?;
            self.sigttou_action = signal::sigaction(signal::SIGTTOU, &self.sigttou_action)?;
        }

        Ok(())
    }

    pub fn unmask(&mut self) -> BiminiResult<()> {
        signal::sigprocmask(
            signal::SigmaskHow::SIG_SETMASK,
            Some(&self.source_signals),
            None,
        )?;

        self.source_signals = signal::SigSet::empty();

        unsafe {
            signal::sigaction(signal::SIGTTIN, &self.sigttin_action)?;
            signal::sigaction(signal::SIGTTOU, &self.sigttou_action)?;
        }

        Ok(())
    }
}

impl Default for SignalConfig {
    fn default() -> Self {
        SignalConfig::new(vec![
            signal::SIGFPE,
            signal::SIGILL,
            signal::SIGSEGV,
            signal::SIGBUS,
            signal::SIGABRT,
            signal::SIGTRAP,
            signal::SIGSYS,
            signal::SIGTTIN,
            signal::SIGTTOU,
        ])
    }
}
