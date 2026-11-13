//! The service's log on Linux, read from the system's journal as the account that runs
//! the GUI. Nothing asks for root: an account that may not read the service's entries
//! gets a line saying how to collect them by hand.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fluent_bundle::FluentArgs;
use rosetun_config::redact_report_text;

use crate::i18n::Language;

const JOURNALCTL: [&str; 2] = ["/usr/bin/journalctl", "/bin/journalctl"];
const UNIT: &str = "rosetun-helper.service";
const LINES: &str = "2000";
const TIMEOUT: Duration = Duration::from_secs(15);
const LIMIT: u64 = 1024 * 1024;

struct Output {
    stdout: String,
    stderr: String,
}

/// What `journalctl -u rosetun-helper -b` prints, cleaned for a report, or the reason it
/// could not be read.
pub(super) fn helper_log(language: Language) -> String {
    let Some(program) = JOURNALCTL.iter().find(|path| Path::new(path).is_file()) else {
        return crate::i18n::tr_in(language, "report-helper-log-no-journal", &FluentArgs::new());
    };
    let Some(output) = run(program) else {
        return crate::i18n::tr_in(
            language,
            "report-helper-log-unavailable",
            &FluentArgs::new(),
        );
    };
    if denied(&output) {
        return crate::i18n::tr_in(
            language,
            "report-helper-log-journal-denied",
            &FluentArgs::new(),
        );
    }
    clean(&output.stdout)
}

fn run(program: &str) -> Option<Output> {
    let mut child = Command::new(program)
        .args([
            "-u",
            UNIT,
            "-b",
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            LINES,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let readers = [drain(child.stdout.take()?), drain(child.stderr.take()?)];
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < TIMEOUT => thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let [stdout, stderr] = readers.map(|reader| reader.join().unwrap_or_default());
    Some(Output { stdout, stderr })
}

fn drain(pipe: impl Read + Send + 'static) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut text = String::new();
        let _ = pipe.take(LIMIT).read_to_string(&mut text);
        text
    })
}

/// journalctl does not fail for an account outside the journal's groups; it says it sees
/// less, or nothing.
fn denied(output: &Output) -> bool {
    let both = format!("{}\n{}", output.stdout, output.stderr);
    both.contains("insufficient permissions") || both.contains("not seeing messages from other")
}

fn clean(text: &str) -> String {
    let lines: Vec<String> = text
        .lines()
        .map(|line| without_host(line.trim_end()))
        .collect();
    let printable: String = lines
        .join("\n")
        .chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' {
                ' '
            } else {
                ch
            }
        })
        .collect();
    redact_report_text(&printable)
}

/// `short-iso` puts the machine's name after the time; a report does not carry it.
fn without_host(line: &str) -> String {
    let timestamped = line.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && line
            .split(' ')
            .next()
            .is_some_and(|time| time.contains('T'));
    if timestamped
        && let Some((time, rest)) = line.split_once(' ')
        && let Some((_host, rest)) = rest.split_once(' ')
    {
        return format!("{time} {rest}");
    }
    line.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_name_is_dropped_from_a_journal_line() {
        assert_eq!(
            without_host("2026-11-13T12:00:00+0900 workstation rosetun-helper[42]: started"),
            "2026-11-13T12:00:00+0900 rosetun-helper[42]: started"
        );
        assert_eq!(without_host("-- Boot abc123 --"), "-- Boot abc123 --");
        assert_eq!(without_host("-- No entries --"), "-- No entries --");
    }

    #[test]
    fn an_account_that_sees_less_gets_the_explanation_not_the_log() {
        let hint = Output {
            stdout: "-- No entries --\n".to_owned(),
            stderr:
                "Hint: You are currently not seeing messages from other users and the system.\n"
                    .to_owned(),
        };
        assert!(denied(&hint));
        let nothing = Output {
            stdout: String::new(),
            stderr: "No journal files were opened due to insufficient permissions.\n".to_owned(),
        };
        assert!(denied(&nothing));
        let fine = Output {
            stdout: "2026-11-13T12:00:00+0900 h rosetun-helper[1]: up\n".to_owned(),
            stderr: String::new(),
        };
        assert!(!denied(&fine));
    }

    #[test]
    fn the_cleaned_log_hides_addresses_and_home_folders() {
        let text = clean(
            "2026-11-13T12:00:00+0900 host rosetun-helper[1]: node 198.51.100.7 from /home/example/x\u{1b}\n",
        );
        assert!(!text.contains("198.51.100.7"), "{text}");
        assert!(!text.contains("example"), "{text}");
        assert!(!text.contains("host "), "{text}");
        assert!(!text.contains('\u{1b}'));
    }
}
