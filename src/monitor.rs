use core::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};

use libafl::prelude::current_time;
use libafl::prelude::{format_duration_hms, ClientId, ClientStats, Monitor};

use crate::fuzz_ui::FuzzUI;

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct HWFuzzMonitor {
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    ui: Arc<Mutex<FuzzUI>>,
    iterations_log_path: String,
    last_iterations_logged: u64,
}

impl Monitor for HWFuzzMonitor {
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, _event_msg: String, sender_id: ClientId) {
        let execs = self.total_execs();
        let execs_per_sec = self.execs_per_sec_pretty();
        {
            let client = self.client_stats_mut_for(sender_id).clone();

            let mut ui = self.ui.lock().unwrap();
            let data = ui.data();

            data.add_corpus_size(self.corpus_size());

            let mut max_coverage : u64 = 0;
            for (key, val) in &client.user_monitor {
                if key == "shared_mem" {
                    // shared_mem has the form:
                    //  BITS/MAX_BITS (PERCENTAGE%)
                    // For example:
                    //  0/2201728 (0%)
                    //  ^ ^^^^^^^
                    // We store these two parts.
                    let str = val.to_string();
                    let bit_str = str.split("/").nth(0).unwrap();
                    let bits = u64::from_str_radix(bit_str, 10).unwrap();
                    data.add_max_coverage(bits as f64);

                    // The second half is the maximum coverage.
                    // This should be constant during the execution.
                    // Changes depending on used coverage, so we log it.
                    let right_side = str.split("/").nth(1).unwrap();
                    let max_str = right_side.split(" (").nth(0).unwrap();
                    max_coverage = u64::from_str_radix(max_str, 10).unwrap();
                }
            }

            let time_since_start = current_time() - self.start_time;

            // Only log every few hundred iterations the time to avoid creating
            // a too large log file.
            let log_every_n_iterations = 500;
            if execs > self.last_iterations_logged + log_every_n_iterations {
                self.last_iterations_logged = execs;

                // Write the current time and iterations to a log file. This can
                // be used to find infer iterations-to-exposure from the
                // time-to-exposure data we log.
                let mut iterations_log = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(&self.iterations_log_path)
                    .expect("Failed to open iterations log file");

                iterations_log
                    .write_all(
                        format!(
                            "{} {} {} {} {}\n",
                            time_since_start.as_secs(),
                            execs,
                            self.corpus_size(),
                            data.get_max_coverage() as u64,
                            max_coverage
                        )
                        .as_bytes(),
                    )
                    .expect("Failed to update iterations log file");
            }

            let mut msg = format!(
                "time: {}, corpus: {}, found: {}, execs: {}, exec/sec: {}",
                format_duration_hms(&(current_time() - self.start_time)),
                self.corpus_size(),
                self.objective_size(),
                execs,
                execs_per_sec,
            );
            for (key, val) in &client.user_monitor {
                msg += format!(", {key}: {val}").as_str();
            }
            data.add_message(msg.to_string());

            if msg.contains("shared_mem") {
                let mut log_msg = format!(
                    "STATUS: {} {} {} {} {} ",
                    (current_time() - self.start_time).as_secs(),
                    self.corpus_size(),
                    self.objective_size(),
                    execs,
                    execs_per_sec,
                );
                for (_key, val) in &client.user_monitor {
                    // Remove bunch of undesired stuff from the key to make it
                    // fully space separated.
                    let mut val_str = format!(" {val}").as_str().to_owned();
                    val_str = val_str.replace("/", " ");
                    val_str = val_str.replace("(", " ");
                    val_str = val_str.replace(")", " ");
                    val_str = val_str.replace("%", " ");
                    log_msg += &val_str;
                }
                log::info!("{}", log_msg);
            }
        }

        let mut ui = self.ui.lock().unwrap();
        ui.try_tick();
    }
}

impl HWFuzzMonitor {
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(ui: Arc<Mutex<FuzzUI>>, out_dir: String) -> Self {
        let log_path = out_dir + "/iterations_time";
        Self {
            start_time: current_time(),
            client_stats: vec![],
            ui,
            iterations_log_path: log_path,
            last_iterations_logged: 0,
        }
    }
}
