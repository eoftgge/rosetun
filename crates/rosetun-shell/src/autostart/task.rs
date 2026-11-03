//! The sign-in task as Task Scheduler XML, and the little read back from it.

use std::path::Path;

/// Normal process priority with a normal thread priority, the same as a
/// program the user starts from Explorer. A task's default, 7, is below
/// normal, and Task Scheduler lowers its I/O and memory priority as well;
/// 4 would raise the GUI's threads above the user's other programs.
pub(super) const PRIORITY: u8 = 5;

/// What the sign-in task runs, and for whom.
#[derive(Debug, Clone, Copy)]
pub(super) struct TaskDefinition<'a> {
    pub(super) user_sid: &'a str,
    pub(super) exe: &'a Path,
    pub(super) argument: &'a str,
    pub(super) description: &'a str,
}

impl TaskDefinition<'_> {
    /// Task Scheduler 1.2 XML: a logon trigger for this user only, without
    /// delay, run with the user's own limited token and no stored password.
    pub(super) fn xml(&self) -> String {
        let sid = escape(self.user_sid);
        let command = escape(&format!("\"{}\"", self.exe.display()));
        let argument = escape(self.argument);
        let description = escape(self.description);
        format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{sid}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{sid}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>false</StartWhenAvailable>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>{PRIORITY}</Priority>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{argument}</Arguments>
    </Exec>
  </Actions>
</Task>
"#
        )
    }
}

/// The program a registered task's XML runs, without quotes.
pub(super) fn command_of(xml: &str) -> Option<String> {
    let start = xml.find("<Command>")? + "<Command>".len();
    let end = start + xml[start..].find("</Command>")?;
    let command = unescape(xml[start..end].trim());
    let command = command
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(&command);
    Some(command.to_owned())
}

/// Whether a task's command names `exe`. Windows paths ignore case.
pub(super) fn runs(command: &str, exe: &Path) -> bool {
    let exe = exe.to_string_lossy();
    let exe = exe.strip_prefix(r"\\?\").unwrap_or(&exe);
    command.to_lowercase() == exe.to_lowercase()
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn definition(exe: &Path) -> TaskDefinition<'_> {
        TaskDefinition {
            user_sid: SID,
            exe,
            argument: "--hidden",
            description: "Starts Rosetun at sign-in",
        }
    }

    fn element<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        xml.match_indices(&open)
            .map(|(at, _)| {
                let start = at + open.len();
                let end = start + xml[start..].find(&close).unwrap();
                &xml[start..end]
            })
            .collect()
    }

    #[test]
    fn the_task_starts_at_this_users_sign_in_without_delay() {
        let xml = definition(Path::new(r"C:\Rosetun\rosetun-gui.exe")).xml();
        assert_eq!(element(&xml, "LogonTrigger").len(), 1);
        assert_eq!(element(&xml, "UserId"), [SID, SID]);
        assert!(element(&xml, "Delay").is_empty());
        assert!(!xml.contains("<BootTrigger>"));
    }

    #[test]
    fn the_task_runs_with_the_users_limited_token_and_no_password() {
        let xml = definition(Path::new(r"C:\Rosetun\rosetun-gui.exe")).xml();
        assert_eq!(element(&xml, "LogonType"), ["InteractiveToken"]);
        assert_eq!(element(&xml, "RunLevel"), ["LeastPrivilege"]);
        assert!(!xml.contains("HighestAvailable"));
        assert!(!xml.contains("Password"));
    }

    #[test]
    fn the_task_runs_without_a_limit_on_battery_at_normal_priority() {
        let xml = definition(Path::new(r"C:\Rosetun\rosetun-gui.exe")).xml();
        assert_eq!(element(&xml, "ExecutionTimeLimit"), ["PT0S"]);
        assert_eq!(element(&xml, "DisallowStartIfOnBatteries"), ["false"]);
        assert_eq!(element(&xml, "StopIfGoingOnBatteries"), ["false"]);
        assert_eq!(element(&xml, "MultipleInstancesPolicy"), ["IgnoreNew"]);
        assert_eq!(element(&xml, "StartWhenAvailable"), ["false"]);
        assert_eq!(element(&xml, "WakeToRun"), ["false"]);
        assert_eq!(element(&xml, "Priority"), ["5"]);
        assert!((4..=6).contains(&PRIORITY));
    }

    #[test]
    fn the_task_starts_the_quoted_gui_hidden() {
        let exe = Path::new(r"C:\Program Files\Rosetun\rosetun-gui.exe");
        let xml = definition(exe).xml();
        assert_eq!(
            element(&xml, "Command"),
            ["&quot;C:\\Program Files\\Rosetun\\rosetun-gui.exe&quot;"]
        );
        assert_eq!(element(&xml, "Arguments"), ["--hidden"]);
        assert_eq!(
            command_of(&xml).as_deref(),
            Some(r"C:\Program Files\Rosetun\rosetun-gui.exe")
        );
    }

    #[test]
    fn markup_in_a_path_or_description_is_escaped() {
        let exe = Path::new(r"C:\A&B <x>\rosetun-gui.exe");
        let mut task = definition(exe);
        task.description = "Rosetun & <friends>";
        let xml = task.xml();
        assert_eq!(
            element(&xml, "Description"),
            ["Rosetun &amp; &lt;friends&gt;"]
        );
        assert_eq!(
            command_of(&xml).as_deref(),
            Some(r"C:\A&B <x>\rosetun-gui.exe")
        );
    }

    #[test]
    fn a_command_read_back_without_quotes_or_with_plain_quotes_is_found() {
        assert_eq!(
            command_of("<Exec><Command>C:\\R\\rosetun-gui.exe</Command></Exec>").as_deref(),
            Some(r"C:\R\rosetun-gui.exe")
        );
        assert_eq!(
            command_of("<Command> \"C:\\R\\rosetun-gui.exe\" </Command>").as_deref(),
            Some(r"C:\R\rosetun-gui.exe")
        );
        assert_eq!(command_of("<Exec></Exec>"), None);
    }

    #[test]
    fn a_command_matches_the_executable_ignoring_case_and_the_long_path_prefix() {
        let exe = Path::new(r"\\?\C:\Program Files\Rosetun\rosetun-gui.exe");
        assert!(runs(r"c:\program files\rosetun\ROSETUN-GUI.exe", exe));
        assert!(!runs(r"D:\Rosetun\rosetun-gui.exe", exe));
    }
}
