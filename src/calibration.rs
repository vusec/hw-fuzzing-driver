extern crate alloc;
use alloc::string::{String, ToString};
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use hashbrown::HashSet;

use serde::{Deserialize, Serialize};

use libafl::{
    bolts::{tuples::Named, AsIter},
    corpus::{Corpus, CorpusId, SchedulerTestcaseMetadata},
    events::{EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::HasObserverName,
    fuzzer::Evaluator,
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple, UsesObserver},
    schedulers::powersched::SchedulerMetadata,
    stages::Stage,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasNamedMetadata, UsesState},
    Error,
};

use crate::program_input::ProgramInput;

libafl::impl_serdeany!(UnstableEntriesMetadata);
/// The metadata to keep unstable entries
/// In libafl, the stability is the number of the unstable entries divided by the size of the map
/// This is different from AFL++, which shows the number of the unstable entries divided by the number of filled entries.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnstableEntriesMetadata {
    unstable_entries: HashSet<usize>,
    map_len: usize,
}

impl UnstableEntriesMetadata {
    #[must_use]
    /// Create a new [`struct@UnstableEntriesMetadata`]
    pub fn new(entries: HashSet<usize>, map_len: usize) -> Self {
        Self {
            unstable_entries: entries,
            map_len,
        }
    }

    /// Getter
    #[must_use]
    pub fn unstable_entries(&self) -> &HashSet<usize> {
        &self.unstable_entries
    }

    /// Getter
    #[must_use]
    pub fn map_len(&self) -> usize {
        self.map_len
    }
}

/// The calibration stage will measure the average exec time and the target's stability for this input.
#[derive(Clone, Debug)]
pub struct DummyCalibration<O, OT, S> {
    map_observer_name: String,
    phantom: PhantomData<(O, OT, S)>,
}

impl<O, OT, S> UsesState for DummyCalibration<O, OT, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<E, EM, O, OT, Z> Stage<E, EM, Z> for DummyCalibration<O, OT, E::State>
where
    E: Executor<EM, Z> + HasObservers<Observers = OT>,
    EM: EventFirer<State = E::State>,
    O: MapObserver,
    for<'de> <O as MapObserver>::Entry: Serialize + Deserialize<'de> + 'static,
    OT: ObserversTuple<E::State>,
    E::State: HasCorpus + HasMetadata + HasClientPerfMonitor + HasNamedMetadata,
    Z: Evaluator<E, EM, State = E::State>,
    ProgramInput: From<<<E as UsesState>::State as UsesInput>::Input>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        mgr: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        // Run this stage only once for each corpus entry and only if we haven't already inspected it
        {
            let corpus = state.corpus().get(corpus_idx)?.borrow();

            if corpus.scheduled_count() > 0 {
                return Ok(());
            }
        }

        // We only ran our program once.
        let iter = 1;

        let input = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input(state.corpus())?
            .clone();

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
            let map = executor
                .observers()
                .match_name::<O>(&self.map_observer_name)
                .ok_or_else(|| Error::key_not_found("MapObserver not found".to_string()))?;

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

            let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
            let scheduled_count = testcase.scheduled_count();

            testcase.set_exec_time(total_time / (iter as u32));
            testcase.set_scheduled_count(scheduled_count + 1);

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
}

impl<O, OT, S> DummyCalibration<O, OT, S>
where
    O: MapObserver,
    OT: ObserversTuple<S>,
    S: HasCorpus + HasMetadata + HasNamedMetadata,
{
    #[must_use]
    pub fn new<F>(map_feedback: &F) -> Self
    where
        F: HasObserverName + Named + UsesObserver<S, Observer = O>,
        for<'it> O: AsIter<'it, Item = O::Entry>,
    {
        Self {
            map_observer_name: map_feedback.observer_name().to_string(),
            phantom: PhantomData,
        }
    }
}
