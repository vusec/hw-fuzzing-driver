use core::marker::PhantomData;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use libafl::prelude::*;
use libafl::{
    corpus::CorpusId,
    stages::Stage,
    Error,
};

use crate::program_input::ProgramInput;

/// Maximum number of consecutive invalid outputs before giving up in a single
/// `perform` call. Prevents infinite loops if the script is misbehaving.
const MAX_REROLL_ATTEMPTS: usize = 16;

// ---------------------------------------------------------------------------
// PipelinedGenerator – manages the long-lived child process
// ---------------------------------------------------------------------------

/// Wraps a long-lived child process whose stdin/stdout are connected via pipes.
///
/// Protocol (per generation):
///   fuzzer  →  `\n`              (request)
///   script  →  `<hex_bytes>\n`   (response: flat hex dump)
struct PipelinedGenerator {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl PipelinedGenerator {
    /// Spawn the generator script.
    ///
    /// On Linux the child gets `PR_SET_PDEATHSIG(SIGTERM)` so the kernel will
    /// automatically send it SIGTERM when the fuzzer (parent) dies – even on
    /// `kill -9`.
    fn spawn(command: &str) -> Result<Self, Error> {
        println!("[ext-gen] spawning pipeline: {}", command);

        let mut child = unsafe {
            Command::new("sh")
                .arg("-c")
                .arg(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()) // let script errors show in terminal
                .pre_exec(|| {
                    // Ask the kernel to SIGTERM this child when its parent exits.
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                    Ok(())
                })
                .spawn()
                .map_err(|e| {
                    Error::illegal_state(format!("Failed to spawn generator: {}", e))
                })?
        };

        let stdin = child.stdin.take().ok_or_else(|| {
            Error::illegal_state("Generator child has no stdin handle")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            Error::illegal_state("Generator child has no stdout handle")
        })?;

        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
        })
    }

    /// Returns `true` when the child is still running.
    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Send `\n`, read one line of hex back, decode to raw bytes.
    fn request_program(&mut self) -> Result<Vec<u8>, GeneratorError> {
        // -- request --
        self.stdin
            .write_all(b"\n")
            .map_err(|e| GeneratorError::Io(format!("write to generator: {}", e)))?;
        self.stdin
            .flush()
            .map_err(|e| GeneratorError::Io(format!("flush generator stdin: {}", e)))?;

        // -- response --
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| GeneratorError::Io(format!("read from generator: {}", e)))?;

        if n == 0 {
            return Err(GeneratorError::Io("generator closed stdout (EOF)".into()));
        }

        let hex = line.trim();
        if hex.is_empty() {
            return Err(GeneratorError::Invalid("empty hex line".into()));
        }

        // decode hex
        let bytes = decode_hex(hex).map_err(|msg| GeneratorError::Invalid(msg))?;

        if bytes.is_empty() {
            return Err(GeneratorError::Invalid("decoded to zero bytes".into()));
        }

        Ok(bytes)
    }

    /// Kill the child (best-effort). Called from `Drop` as well.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for PipelinedGenerator {
    fn drop(&mut self) {
        self.kill();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Categorise generator errors so the stage knows whether to respawn or reroll.
enum GeneratorError {
    /// The pipe / process is broken → need respawn.
    Io(String),
    /// The script produced something we can't use → warn & reroll.
    Invalid(String),
}

/// Decode a hex string (e.g. `"0A1B2C3D"`) into bytes. Accepts optional `0x`
/// prefix. Must have an even number of hex characters.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim_start_matches("0x").trim_start_matches("0X");

    if hex.len() % 2 != 0 {
        return Err(format!(
            "odd number of hex characters ({}): '{}'",
            hex.len(),
            hex
        ));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("bad hex '{}': {}", byte_str, e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// ExternalGeneratorStage
// ---------------------------------------------------------------------------

/// A stage that generates programs by communicating with a long-lived external
/// process over stdin/stdout pipes.
///
/// * Fuzzer sends `\n` to request a program.
/// * Script replies with a single line of hex-encoded bytes (flat dump) + `\n`.
/// * The hex output must have an even number of hex characters (whole bytes).
///
/// If the script dies it is automatically respawned. If it produces invalid
/// output, a warning is printed and the stage re-requests (up to
/// [`MAX_REROLL_ATTEMPTS`] times per `perform` call).
///
/// The child process receives `SIGTERM` from the kernel when the fuzzer exits
/// (via `PR_SET_PDEATHSIG`), and is also killed in `Drop`.
pub struct ExternalGeneratorStage<E, EM, Z> {
    command: String,
    generator: Option<PipelinedGenerator>,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> ExternalGeneratorStage<E, EM, Z> {
    pub fn new(command: String) -> Self {
        Self {
            command,
            generator: None,
            phantom: PhantomData,
        }
    }

    /// Ensure we have a live child process, (re)spawning if necessary.
    fn ensure_alive(&mut self) -> Result<(), Error> {
        let needs_spawn = match self.generator {
            Some(ref mut g) => !g.is_alive(),
            None => true,
        };

        if needs_spawn {
            // Drop the old one first (kills it cleanly).
            self.generator.take();
            self.generator = Some(PipelinedGenerator::spawn(&self.command)?);
        }

        Ok(())
    }

    /// Request a program, handling respawns and invalid-output rerolls.
    fn generate_program(&mut self) -> Result<Vec<u8>, Error> {
        for attempt in 0..MAX_REROLL_ATTEMPTS {
            self.ensure_alive()?;

            let gen = self.generator.as_mut().unwrap();

            match gen.request_program() {
                Ok(bytes) => return Ok(bytes),

                Err(GeneratorError::Io(msg)) => {
                    eprintln!(
                        "[ext-gen] pipe/process error (will respawn): {}",
                        msg
                    );
                    // Force respawn on next iteration.
                    self.generator.take();
                }

                Err(GeneratorError::Invalid(msg)) => {
                    eprintln!(
                        "[ext-gen] invalid output (attempt {}/{}): {}",
                        attempt + 1,
                        MAX_REROLL_ATTEMPTS,
                        msg,
                    );
                    // Generator is still alive, just reroll.
                }
            }
        }

        Err(Error::illegal_state(format!(
            "Generator failed after {} attempts",
            MAX_REROLL_ATTEMPTS
        )))
    }
}

/// Kill the child when the stage is dropped (fuzzer exits normally).
impl<E, EM, Z> Drop for ExternalGeneratorStage<E, EM, Z> {
    fn drop(&mut self) {
        self.generator.take(); // triggers PipelinedGenerator::drop → kill
    }
}

impl<E, EM, Z> UsesState for ExternalGeneratorStage<E, EM, Z>
where
    Z: UsesState,
{
    type State = Z::State;
}

impl<E, EM, Z> Stage<E, EM, Z> for ExternalGeneratorStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasRand + HasClientPerfMonitor + HasCorpus<Input = ProgramInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let raw_bytes = self.generate_program()?;
        let input = ProgramInput::from_raw_bytes(raw_bytes);

        // Runs the input through executor + feedback, same as normal fuzzing.
        // If the input triggers new coverage → added to corpus.
        // If it triggers a crash → added to objectives.
        fuzzer.add_input(state, executor, manager, input)?;

        Ok(())
    }
}