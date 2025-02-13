use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::Command,
    time::{Duration, UNIX_EPOCH},
};

pub const FUZZING_CAUSE_DIR_VAR: &'static str = "FUZZING_CAUSE_DIR";
pub const FUZZING_EXPECTED_LIST_VAR: &'static str = "FUZZING_EXPECTED_LIST";

pub struct TestCaseData {
    pub cause: String,
    pub time_to_exposure: Duration,
}

fn get_found_all_path() -> String {
    let cause_dir =
        std::env::var(FUZZING_CAUSE_DIR_VAR).expect("Driver failed to set cause env var?");
    cause_dir + "/../found_all"
}

fn get_expected() -> HashSet<String> {
    let expected_path = std::env::var(FUZZING_EXPECTED_LIST_VAR)
        .expect("Failed to set FUZZING_EXPECTED_LIST env var?");

    let file = File::open(expected_path).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .filter(|l| !l.is_empty())
        .collect()
}

pub struct CausesList {
    pub found: Vec<TestCaseData>,
    pub still_missing: Vec<String>,
}

pub fn list_causes(start_time: std::time::Duration) -> CausesList {
    let cause_dir =
        std::env::var(FUZZING_CAUSE_DIR_VAR).expect("Driver failed to set cause env var?");

    let causes = std::fs::read_dir(Path::new(&cause_dir)).expect("Failed to read causes dir");

    let mut expected = get_expected();

    let mut case_list = Vec::<TestCaseData>::new();
    for cause_or_err in causes {
        let cause = cause_or_err.unwrap();
        let creation_time = cause.metadata().unwrap().created().unwrap();
        let creation_unix_time = creation_time.duration_since(UNIX_EPOCH).unwrap();
        let diff_time = creation_unix_time - start_time;

        let filename = cause.file_name().into_string().unwrap();
        let cause_str = filename
            .split("%")
            .nth(0)
            .or(Some("Bad cause name"))
            .unwrap();
        let display_str = cause_str.replace("_", " ");

        expected.remove(&display_str);

        case_list.push(TestCaseData {
            cause: display_str.to_string(),
            time_to_exposure: diff_time,
        })
    }

    case_list.sort_by_key(|t| t.time_to_exposure);

    let mut missing = Vec::<String>::new();
    for m in expected {
        missing.push(m);
    }
    missing.sort();

    if missing.is_empty() {
        let mut results =
            File::create(get_found_all_path()).expect("Failed to create found_all_path");

        for case in &case_list {
            results
                .write_all(
                    format!("{} $ {}\n", case.time_to_exposure.as_secs(), case.cause).as_bytes(),
                )
                .expect("Failed to write results");
        }
        results.flush().expect("Failed to flush results file");

        // Run killall to stop the fuzzer.
        // FIXME: That cann't be the only way to stop the fuzzer, but it seems
        // it is...
        Command::new("killall")
            .arg("sim-fuzzer")
            .spawn()
            .expect("Failed to stop sim-fuzzer:");
    }

    CausesList {
        found: case_list,
        still_missing: missing,
    }
}
