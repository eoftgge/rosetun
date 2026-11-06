//! Changes the desktop's proxy settings the way the GUI does, for test machines
//! where the GUI cannot run. Never shipped; `tools/vm` drives it.
//!
//! ```text
//! desktop_proxy set <record file> <port>
//! desktop_proxy restore <record file>
//! ```
//!
//! Prints what happened on one line. Exiting without `restore` is what a crash
//! of the GUI leaves behind.

use std::path::PathBuf;
use std::process::ExitCode;

use rosetun_shell::DesktopProxy;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let outcome = match arguments.as_slice() {
        ["set", record, port] => match port.parse() {
            Ok(port) => DesktopProxy::new(PathBuf::from(record))
                .set(port)
                .map(|set| format!("{set:?}")),
            Err(_) => {
                eprintln!("the port must be a number");
                return ExitCode::from(64);
            }
        },
        ["restore", record] => DesktopProxy::new(PathBuf::from(record))
            .restore()
            .map(|restore| format!("{restore:?}")),
        _ => {
            eprintln!("usage: desktop_proxy set <record> <port> | restore <record>");
            return ExitCode::from(64);
        }
    };
    match outcome {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
