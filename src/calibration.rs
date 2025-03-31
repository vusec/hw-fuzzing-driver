use core::{fmt::Debug, marker::PhantomData, time::Duration};
use std::borrow::Cow;

use std::collections::HashSet;
use libafl_bolts::{impl_serdeany, AsIter, Named, tuples::Handle};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId, SchedulerTestcaseMetadata},
    events::{EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{HasObserverHandle},
    fuzzer::Evaluator,
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    schedulers::powersched::SchedulerMetadata,
    stages::{RetryCountRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions},
    Error, HasMetadata, HasNamedMetadata,
};

use crate::program_input::ProgramInput;

/// Default name for `CalibrationStage`; derived from AFL++
const CALIBRATION_STAGE_NAME: &str = "calibration";

/// The metadata to keep unstable entries
/// Formula is same as AFL++: number of unstable entries divided by the number of filled entries.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnstableEntriesMetadata {
    unstable_entries: HashSet<usize>,
    filled_entries_count: usize,
}
impl_serdeany!(UnstableEntriesMetadata);

impl UnstableEntriesMetadata {
    #[must_use]
    /// Create a new [`struct@UnstableEntriesMetadata`]
    pub fn new(entries: HashSet<usize>, map_len: usize) -> Self {
        Self {
            unstable_entries: entries,
            filled_entries_count: map_len,
        }
    }

    /// Getter
    #[must_use]
    pub fn unstable_entries(&self) -> &HashSet<usize> {
        &self.unstable_entries
    }

    /// Getter
    #[must_use]
    pub fn filled_entries_count(&self) -> usize {
        self.filled_entries_count
    }
}

/// The calibration stage will measure the average exec time and the target's stability for this input.
#[derive(Clone, Debug)]
pub struct DummyCalibration<C, E, I, O, OT, S> {
    map_observer_handle: Handle<C>,
    map_name: Cow<'static, str>,
    name: Cow<'static, str>,
    phantom: PhantomData<(C, E, I, O, OT, S)>,
}

// impl<C, E, I, O, OT, S> UsesState for DummyCalibration<C, E, I, O, OT, S>
// where
//     S: UsesInput,
// {
//     type State = S;
// }

impl<C, E, EM, I, O, OT, S, Z> Stage<E, EM, S, Z> for DummyCalibration<C, E, I, O, OT, S>
where
    E: Executor<EM, I, S, Z> + HasObservers<Observers = OT>,
    EM: EventFirer<I, S>,
    O: MapObserver,
    C: AsRef<O>,
    for<'de> <O as MapObserver>::Entry:
        Serialize + Deserialize<'de> + 'static + Default + Debug + Bounded,
    OT: ObserversTuple<I, S>,
    S: HasCorpus<I>
        + HasMetadata
        + HasNamedMetadata
        + HasExecutions
        + HasCurrentTestcase<I>
        + HasCurrentCorpusId,
    Z: Evaluator<E, EM, I, S>,
    I: Input,
    ProgramInput: From<I>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        mgr: &mut EM,
    ) -> Result<(), Error> {
        // Run this stage only once for each corpus entry and only if we haven't already inspected it
        {
            let testcase = state.current_testcase()?;
            // println!("calibration; corpus.scheduled_count() : {}",  testcase.scheduled_count());

            if testcase.scheduled_count() > 0 {
                return Ok(());
            }
        }

        // We only ran our program once.
        let iter = 1;

        let input = state.current_input_cloned()?;
        executor.observers_mut().pre_exec_all(state, &input)?;

        let exit_kind = executor.run_target(fuzzer, state, mgr, &input)?;

        if exit_kind != ExitKind::Ok {
            mgr.log(
                state,
                LogSeverity::Warn,
                "Corpus entry errored on execution!".into(),
            )?;
        };

        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;


        // Estimate duration based on number of instructions.
        let program: ProgramInput = input.into();
        let total_time = Duration::from_secs((program.insts().len() + 1) as u64);

        // If weighted scheduler or powerscheduler is used, update it
        if state.has_metadata::<SchedulerMetadata>() {
            let observers = executor.observers();
            let map = observers[&self.map_observer_handle].as_ref();

            let bitmap_size = map.count_bytes();

            let psmeta = state
                .metadata_map_mut()
                .get_mut::<SchedulerMetadata>()
                .unwrap();
            let handicap = psmeta.queue_cycles();

            psmeta.set_exec_time(psmeta.exec_time() + total_time);
            psmeta.set_cycles(psmeta.cycles() + (iter as u64));
            psmeta.set_bitmap_size(psmeta.bitmap_size() + bitmap_size);
            psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() + libm::log2(bitmap_size as f64));
            psmeta.set_bitmap_entries(psmeta.bitmap_entries() + 1);

            let mut testcase = state.current_testcase_mut()?;

            testcase.set_exec_time(total_time / (iter as u32));

            // If the testcase doesn't have its own `SchedulerTestcaseMetadata`, create it.
            let data = if let Ok(metadata) = testcase.metadata_mut::<SchedulerTestcaseMetadata>() {
                metadata
            } else {
                let depth = if let Some(parent_id) = testcase.parent_id() {
                    if let Some(parent_metadata) = (*state.corpus().get(parent_id)?)
                        .borrow()
                        .metadata_map()
                        .get::<SchedulerTestcaseMetadata>()
                    {
                        parent_metadata.depth() + 1
                    } else {
                        0
                    }
                } else {
                    0
                };
                testcase.add_metadata(SchedulerTestcaseMetadata::new(depth));
                testcase
                    .metadata_mut::<SchedulerTestcaseMetadata>()
                    .unwrap()
            };

            data.set_cycle_and_time((total_time, iter));
            data.set_bitmap_size(bitmap_size);
            data.set_handicap(handicap);
        }

        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // Calibration stage disallow restarts
        // If a testcase that causes crash/timeout in the queue, we need to remove it from the queue immediately.
        RetryCountRestartHelper::no_retry(state, &self.name)

        // todo
        // remove this guy from corpus queue
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        // TODO: Make sure this is the correct way / there may be a better way?
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<C, E, I, O, OT, S> DummyCalibration<C, E, I, O, OT, S>
where
    C: AsRef<O>,
    O: MapObserver,
    for<'it> O: AsIter<'it, Item = O::Entry>,
    OT: ObserversTuple<I, S>,
{
    #[must_use]
    pub fn new<F>(map_feedback: &F) -> Self
    where
        F: HasObserverHandle<Observer = C> + Named,
    {
        let map_name = map_feedback.name().clone();
        Self {
            map_observer_handle: map_feedback.observer_handle().clone(),
            map_name: map_name.clone(),
            phantom: PhantomData,
            name: Cow::Owned(
                CALIBRATION_STAGE_NAME.to_owned() + ":" + map_name.into_owned().as_str(),
            ),
        }
    }
}

impl<C, E, I, O, OT, S> Named for DummyCalibration<C, E, I, O, OT, S> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
