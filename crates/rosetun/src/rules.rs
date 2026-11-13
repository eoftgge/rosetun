use std::io::{self, BufRead, Read, Write};

use rosetun_config::{RuleId, RuleTarget, rules_exchange::{self, System}};
use rosetun_core::{Store, terminal_text};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Export { selected: Option<Vec<RuleId>>, urls: bool, path: String },
    Import { replace: bool, yes: bool, path: String },
}
pub(crate) fn parse(args: &[&str]) -> Result<Command, String> {
    let usage = "rules export [--selected-ids ID,...] [--with-list-urls] [FILE|-] or rules import [--replace] [--yes] FILE|-";
    let Some((&kind, args)) = args.split_first() else { return Err(usage.into()); };
    let mut selected = None; let mut urls = false; let mut replace = false; let mut yes = false; let mut path = None;
    let mut args = args.iter();
    while let Some(&arg) = args.next() {
        match (kind,arg) {
            ("export","--selected-ids") if selected.is_none() => {
                let ids = args.next().ok_or(usage)?.split(',').map(RuleId::new).collect::<Vec<_>>();
                if ids.iter().any(|id| id.as_str().is_empty() || id.as_str().starts_with('-')) { return Err(usage.into()); }
                selected = Some(ids);
            }
            ("export","--with-list-urls") if !urls => urls = true,
            ("import","--replace") if !replace => replace = true,
            ("import","--yes") if !yes => yes = true,
            (_,value) if (value == "-" || !value.starts_with('-')) && path.is_none() => path = Some(value.to_owned()),
            _ => return Err(usage.into()),
        }
    }
    match kind {
        "export" => Ok(Command::Export { selected, urls, path:path.unwrap_or_else(|| "-".into()) }),
        "import" => Ok(Command::Import { replace, yes, path:path.ok_or(usage)? }),
        _ => Err(usage.into()),
    }
}
fn confirm(label: &str, console: bool) -> Result<bool, String> {
    eprint!("{label} [y/N] "); io::stderr().flush().map_err(|_| "could not write prompt")?;
    let mut answer=String::new();
    if console {
        let path=if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
        let input=std::fs::File::open(path).map_err(|_| "confirmation requires a terminal; review the preview and retry with --yes")?;
        io::BufReader::new(input).read_line(&mut answer).map_err(|_| "could not read confirmation")?;
    } else { io::stdin().lock().read_line(&mut answer).map_err(|_| "could not read confirmation")?; }
    Ok(answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes"))
}
pub(crate) fn run(command: Command) -> Result<(),String> {
    let store=Store::open_default().map_err(|error| error.to_string())?;
    let config=store.load().map_err(|error| error.to_string())?;
    let set=config.active_rules().ok_or("select a rule set first")?;
    match command {
        Command::Export { selected, urls, path } => {
            if selected.as_ref().is_some_and(|ids| ids.iter().any(|id| !set.rules.iter().any(|rule| &rule.id == id))) { return Err("selected rule does not exist".into()); }
            let text=rules_exchange::export(&config,set,selected.as_deref(),urls,System::current()).map_err(|error| error.to_string())?;
            if path == "-" { println!("{text}"); } else { std::fs::write(path,text).map_err(|_| "could not write rules file")?; }
        }
        Command::Import { replace, yes, path } => {
            let console = path == "-";
            let input: Box<dyn Read> = if path == "-" { Box::new(io::stdin()) } else { Box::new(std::fs::File::open(path).map_err(|_| "could not read rules file")?) };
            let mut text=String::new(); input.take((rules_exchange::MAX_DOCUMENT_BYTES+1) as u64).read_to_string(&mut text).map_err(|_| "could not read rules document")?;
            let document=rules_exchange::parse(&text).map_err(|error| error.to_string())?;
            let preview=rules_exchange::preview(&document,&config,set,replace,System::current());
            eprintln!("Add {} rules · Skip {} duplicates · Disable {} rules · Invalid {}",preview.rules.len(),preview.duplicates,preview.rules.iter().filter(|rule| !rule.enabled).count(),preview.entries.iter().filter(|entry| entry.invalid).count());
            for rule in &preview.rules { eprintln!("{} → {}{}",terminal_text(&rosetun_core::rule_value_text(&rule.matcher)),target_text(rule.target),if rule.enabled { "" } else { " (disabled)" }); }
            for entry in &preview.entries { for warning in &entry.warnings { eprintln!("Rule {}: {}",entry.index+1,warning_text(*warning)); } }
            if document.default_target == Some(RuleTarget::Direct) { eprintln!("Warning: the imported default sends traffic directly"); }
            let change_default = if !yes && let Some(target)=document.default_target { confirm(&format!("Replace default rule: {}?",target_text(target)),console)? } else { false };
            if !yes && !confirm(if replace { "Replace rules?" } else { "Add rules?" },console)? { return Ok(()); }
            rosetun_core::rules_exchange::apply(&store,&set.id,&preview,replace,change_default).map_err(|error| error.to_string())?;
            eprintln!("Added {} rules",preview.rules.len());
        }
    }
    Ok(())
}
fn warning_text(warning: rules_exchange::Warning) -> &'static str {
    use rules_exchange::Warning;
    match warning { Warning::OtherSystem=>"for another system",Warning::NeedsList=>"list required",Warning::NeedsFile=>"list file required",Warning::ExitReplaced=>"server unavailable; use VPN",Warning::BroadDirect=>"warning: broad rule sends traffic directly" }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parser_checks_exchange_options() {
        assert!(matches!(parse(&["export"]),Ok(Command::Export{urls:false,..})));
        assert!(matches!(parse(&["export","--selected-ids","1,2","--with-list-urls","-"]),Ok(Command::Export{urls:true,..})));
        assert!(matches!(parse(&["import","--replace","--yes","-"]),Ok(Command::Import{replace:true,yes:true,..})));
        for args in [vec!["import"],vec!["export","--yes"],vec!["export","a","b"],vec!["import","--with-list-urls","a"],vec!["export","--selected-ids","--with-list-urls"]] { assert!(parse(&args).is_err()); }
    }
}

fn target_text(target: RuleTarget) -> &'static str {
    match target { RuleTarget::Proxy => "Through VPN", RuleTarget::Direct => "Direct", RuleTarget::Block => "Block", RuleTarget::Exit => "Through server" }
}
