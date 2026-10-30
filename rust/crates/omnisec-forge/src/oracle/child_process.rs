//! [`ChildProcessOracle`] — Stage-4 sandbox using a real host subprocess.
//!
//! # What it does
//!
//! Spawns a configured command with the synthesized payload piped into
//! stdin, reads stdout/stderr, waits up to `timeout` for the child to
//! exit, and compares the result against a [`ProcessVerdict`] — the
//! expected exit code and/or a substring that must appear in stdout for
//! a "successful" run.
//!
//! # What it does NOT do
//!
//! It is **not** a hermetic sandbox. The child runs with the host
//! process's UID, FS access, and network. A real sandbox (QEMU
//! user-mode, `prctl`-jail, hardware-glitch driver) is platform-
//! specific and left as an integration point. The trait
//! [`ChildProcessOracle`] implements the *interface* — it's the piece
//! that lets a caller wire its sandbox of choice into the Forge
//! without changing any Forge-side code.
//!
//! For local validation runs (e.g. ROP-chain prints "hello" to stdout,
//! DOP payload sets `is_admin=1` then the target prints
//! "authenticated"), this oracle is enough.
//!
//! # Determinism
//!
//! Process execution is inherently non-deterministic (scheduler, PID,
//! timing). The oracle therefore only asserts facts the caller
//! specifies (exit code, stdout substring). It never feeds the result
//! back into any randomness source — so using it or not using it
//! leaves `Forge::synthesize` output byte-identical.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use omnisec_json::{FromJson, ToJson};

use crate::payload::SynthesizedPayload;

use super::verification::{Oracle, OracleVerdict};

/// What the caller considers "successful" execution of the payload.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct ProcessVerdict {
    /// Required exit code. `None` means "any exit code is fine".
    pub expected_exit: Option<i32>,
    /// Stdout must contain this substring for success. Empty means
    /// "no stdout check".
    pub expected_stdout_substring: String,
    /// Stderr must NOT contain this substring (e.g. "stack smashing
    /// detected"). Empty means "no stderr check".
    pub forbidden_stderr_substring: String,
}

impl ProcessVerdict {
    /// Build a verdict that only checks the exit code.
    #[must_use]
    pub fn exit_code(code: i32) -> Self {
        Self {
            expected_exit: Some(code),
            expected_stdout_substring: String::new(),
            forbidden_stderr_substring: String::new(),
        }
    }

    /// Build a verdict that requires a substring in stdout.
    #[must_use]
    pub fn stdout_contains(needle: impl Into<String>) -> Self {
        Self {
            expected_exit: None,
            expected_stdout_substring: needle.into(),
            forbidden_stderr_substring: String::new(),
        }
    }
}

/// Real sandbox oracle: spawns a child process, pipes the payload,
/// watches the result.
#[derive(Debug, Clone)]
pub struct ChildProcessOracle {
    /// Program to spawn.
    program: String,
    /// Arguments passed to the program (before the payload).
    args: Vec<String>,
    /// How long to wait for the child to exit before killing it.
    timeout: Duration,
    /// What counts as a successful run.
    verdict: ProcessVerdict,
    /// How to feed the payload to the child. `Stdin` is the default and
    /// the simplest: the payload bytes are written to the child's stdin
    /// before closing it.
    feed: PayloadFeed,
}

/// How the payload is delivered to the child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFeed {
    /// Write payload to stdin, then close stdin.
    Stdin,
    /// Append payload as the last argv slot (hex-encoded).
    ArgvHex,
}

impl ChildProcessOracle {
    /// Build a new oracle that spawns `program` with `args`.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(5),
            verdict: ProcessVerdict {
                expected_exit: Some(0),
                expected_stdout_substring: String::new(),
                forbidden_stderr_substring: String::new(),
            },
            feed: PayloadFeed::Stdin,
        }
    }

    /// Add a positional argument.
    #[must_use]
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Override the timeout (default 5 s).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the success verdict.
    #[must_use]
    pub fn with_verdict(mut self, verdict: ProcessVerdict) -> Self {
        self.verdict = verdict;
        self
    }

    /// Override the payload feed mechanism.
    #[must_use]
    pub fn with_feed(mut self, feed: PayloadFeed) -> Self {
        self.feed = feed;
        self
    }
}

impl Oracle for ChildProcessOracle {
    fn verify(&self, payload: &SynthesizedPayload) -> OracleVerdict {
        let mut notes: Vec<String> = Vec::new();
        notes.push(format!(
            "ChildProcessOracle spawning `{}` with {} byte payload (feed = {:?}, timeout = {:?})",
            self.program,
            payload.payload.len(),
            self.feed,
            self.timeout,
        ));

        let mut cmd = Command::new(&self.program);
        for a in &self.args {
            cmd.arg(a);
        }
        if self.feed == PayloadFeed::ArgvHex {
            let hex: String = payload.payload.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });
            cmd.arg(hex);
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let spawn_result = cmd.spawn();
        let mut child = match spawn_result {
            Ok(c) => c,
            Err(e) => {
                notes.push(format!("spawn failed: {e}"));
                return OracleVerdict {
                    success: false,
                    notes,
                    adjusted_complexity: payload.complexity.raw(),
                };
            }
        };

        if self.feed == PayloadFeed::Stdin
            && let Some(stdin) = child.stdin.as_mut()
            && let Err(e) = stdin.write_all(&payload.payload)
        {
            notes.push(format!("stdin write failed: {e}"));
        }
        // Close stdin by dropping it.
        drop(child.stdin.take());

        // Poll for exit with a soft timeout.
        let start = Instant::now();
        let poll_every = Duration::from_millis(10);
        let exit = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if start.elapsed() >= self.timeout {
                        break None;
                    }
                    std::thread::sleep(poll_every);
                }
                Err(e) => {
                    notes.push(format!("try_wait failed: {e}"));
                    let _ = child.kill();
                    return OracleVerdict {
                        success: false,
                        notes,
                        adjusted_complexity: payload.complexity.raw(),
                    };
                }
            }
        };

        if exit.is_none() {
            notes.push(format!(
                "child exceeded timeout ({:?}); killed",
                self.timeout
            ));
            let _ = child.kill();
            let _ = child.wait();
            return OracleVerdict {
                success: false,
                notes,
                adjusted_complexity: payload.complexity.raw().saturating_add(1_000),
            };
        }

        let status = exit.expect("just-checked Some");
        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                notes.push(format!("wait_with_output failed: {e}"));
                return OracleVerdict {
                    success: false,
                    notes,
                    adjusted_complexity: payload.complexity.raw(),
                };
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        let mut success = true;
        if let Some(want) = self.verdict.expected_exit {
            let got = status.code().unwrap_or(-1);
            if got != want {
                success = false;
                notes.push(format!("exit code {got} ≠ expected {want}"));
            }
        }
        if !self.verdict.expected_stdout_substring.is_empty()
            && !stdout.contains(&self.verdict.expected_stdout_substring)
        {
            success = false;
            notes.push(format!(
                "stdout missing expected substring `{}`",
                self.verdict.expected_stdout_substring
            ));
        }
        if !self.verdict.forbidden_stderr_substring.is_empty()
            && stderr.contains(&self.verdict.forbidden_stderr_substring)
        {
            success = false;
            notes.push(format!(
                "stderr contains forbidden substring `{}`",
                self.verdict.forbidden_stderr_substring
            ));
        }

        if success {
            notes.push("all verdict conditions satisfied".into());
        }
        // Attach the actual stdout/stderr (truncated) for forensic record.
        let max_capture = 512;
        notes.push(format!(
            "stdout[..{}] = {:?}",
            stdout.len().min(max_capture),
            &stdout[..stdout.len().min(max_capture)]
        ));
        if !stderr.is_empty() {
            notes.push(format!(
                "stderr[..{}] = {:?}",
                stderr.len().min(max_capture),
                &stderr[..stderr.len().min(max_capture)]
            ));
        }

        OracleVerdict {
            success,
            notes,
            adjusted_complexity: payload.complexity.raw(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForgeConfig;
    use crate::complexity::ComplexityScore;
    use crate::payload::{SynthesizedPayload, Witness};
    use omnisec_core::Arch;

    fn fake_payload(bytes: Vec<u8>) -> SynthesizedPayload {
        SynthesizedPayload {
            config: ForgeConfig::for_arch(Arch::X86_64),
            primitive: "test".into(),
            arch: Arch::X86_64,
            bypassed: vec![],
            witness: Witness::new(),
            chain: vec![],
            payload: bytes,
            report: vec![],
            complexity: ComplexityScore::TRIVIAL,
            artifacts: vec![],
        }
    }

    /// Find a cross-platform "cat stdin and echo success" shell invocation.
    /// Returns `None` if we're on a platform without either.
    fn echo_oracle() -> Option<ChildProcessOracle> {
        #[cfg(unix)]
        {
            Some(
                ChildProcessOracle::new("sh")
                    .arg("-c")
                    .arg("cat >/dev/null && printf SUCCESS")
                    .with_verdict(ProcessVerdict::stdout_contains("SUCCESS")),
            )
        }
        #[cfg(windows)]
        {
            // `cmd.exe /c` with a no-op pipeline that echoes SUCCESS.
            // We ignore stdin content — Windows cmd has no `cat`
            // equivalent as a one-liner.
            Some(
                ChildProcessOracle::new("cmd")
                    .arg("/c")
                    .arg("echo SUCCESS")
                    .with_verdict(ProcessVerdict::stdout_contains("SUCCESS")),
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }

    #[test]
    fn success_when_stdout_matches() {
        let Some(oracle) = echo_oracle() else { return };
        let verdict = oracle.verify(&fake_payload(b"ignored".to_vec()));
        assert!(verdict.success, "notes = {:?}", verdict.notes);
    }

    #[test]
    fn failure_when_stdout_missing_substring() {
        #[cfg(unix)]
        let oracle = ChildProcessOracle::new("sh")
            .arg("-c")
            .arg("printf NOPE")
            .with_verdict(ProcessVerdict::stdout_contains("YES"));
        #[cfg(windows)]
        let oracle = ChildProcessOracle::new("cmd")
            .arg("/c")
            .arg("echo NOPE")
            .with_verdict(ProcessVerdict::stdout_contains("YES"));
        #[cfg(not(any(unix, windows)))]
        return;
        #[allow(unreachable_code)]
        let verdict = oracle.verify(&fake_payload(vec![]));
        assert!(!verdict.success);
    }

    #[test]
    fn failure_when_spawn_fails() {
        let oracle = ChildProcessOracle::new("/nonexistent/definitely/missing");
        let verdict = oracle.verify(&fake_payload(vec![]));
        assert!(!verdict.success);
        assert!(verdict.notes.iter().any(|n| n.contains("spawn failed")));
    }

    #[test]
    fn failure_when_child_exceeds_timeout() {
        #[cfg(unix)]
        let oracle = ChildProcessOracle::new("sh")
            .arg("-c")
            .arg("sleep 2")
            .with_timeout(Duration::from_millis(150));
        #[cfg(windows)]
        let oracle = ChildProcessOracle::new("cmd")
            .arg("/c")
            .arg("ping -n 3 127.0.0.1 >NUL")
            .with_timeout(Duration::from_millis(150));
        #[cfg(not(any(unix, windows)))]
        return;
        #[allow(unreachable_code)]
        let verdict = oracle.verify(&fake_payload(vec![]));
        assert!(!verdict.success);
        assert!(verdict.notes.iter().any(|n| n.contains("exceeded timeout")));
    }
}
