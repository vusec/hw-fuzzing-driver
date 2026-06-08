use std::fmt;
use std::path::PathBuf;

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{Input, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

pub struct SavingExecutor<E> {
    inner: E,
    save_dir: Option<PathBuf>,
    counter: usize,
}

impl<E> SavingExecutor<E> {
    pub fn new(inner: E, save_dir: Option<PathBuf>) -> Self {
        Self {
            inner,
            save_dir,
            counter: 0,
        }
    }
}

impl<E: fmt::Debug> fmt::Debug for SavingExecutor<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavingExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<E> UsesState for SavingExecutor<E>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E> UsesObservers for SavingExecutor<E>
where
    E: UsesObservers,
{
    type Observers = E::Observers;
}

impl<E> HasObservers for SavingExecutor<E>
where
    E: HasObservers,
{
    fn observers(&self) -> &Self::Observers {
        self.inner.observers()
    }

    fn observers_mut(&mut self) -> &mut Self::Observers {
        self.inner.observers_mut()
    }
}

impl<E, EM, Z> Executor<EM, Z> for SavingExecutor<E>
where
    E: Executor<EM, Z>,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
    <E::State as UsesInput>::Input: Input,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        if let Some(ref dir) = self.save_dir {
            let name = input.generate_name(self.counter);
            self.counter += 1;
            let _ = input.to_file(dir.join(name));
        }
        self.inner.run_target(fuzzer, state, mgr, input)
    }
}
