//! A SIGTERM sent to the whole helper process reaches only its signal
//! thread and ends the process through the shutdown path with code 0; a
//! second signal during that shutdown does not cut it short. This needs a
//! process whose first thread blocks the signals before any other thread
//! starts, which the test harness cannot give, hence `harness = false`.

#[cfg(target_os = "linux")]
#[path = "../src/signals.rs"]
mod signals;

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::signals;

    const CHILD: &str = "ROSETUN_SIGNAL_SHUTDOWN_CHILD";

    pub(super) fn run() {
        if std::env::var_os(CHILD).is_some() {
            child();
        } else {
            parent();
            println!("signal_shutdown: 1 passed");
        }
    }

    /// Stands in for the helper's `main`: block first, then threads, then
    /// wait for the shutdown request and run a teardown that takes a while.
    fn child() {
        let blocked = signals::block().expect("block termination signals");
        // An ordinary worker, as the helper has many: it must not take the signal.
        thread::spawn(|| {
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        });
        let (sender, receiver) = mpsc::channel();
        signals::spawn_waiter(blocked, move |name| {
            let _ = sender.send(name);
        })
        .expect("start the signal waiter");
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "ready").unwrap();
        stdout.flush().unwrap();
        let name = receiver.recv().expect("shutdown request");
        writeln!(stdout, "stopping on {name}").unwrap();
        stdout.flush().unwrap();
        thread::sleep(Duration::from_millis(500));
        writeln!(stdout, "teardown done").unwrap();
        stdout.flush().unwrap();
    }

    fn signal(pid: u32, signal: libc::c_int) {
        let pid = libc::pid_t::try_from(pid).expect("pid fits pid_t");
        // SAFETY: Plain values; the pid is our own unreaped child, so it
        // cannot name another process.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
    }

    fn parent() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the child");
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut next = || lines.next().expect("child line").expect("child output");
        assert_eq!(next(), "ready");
        signal(child.id(), libc::SIGTERM);
        assert_eq!(next(), "stopping on SIGTERM");
        signal(child.id(), libc::SIGINT);
        signal(child.id(), libc::SIGTERM);
        assert_eq!(next(), "teardown done");

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("the child did not exit after its teardown");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(0), "{status}");
    }
}
