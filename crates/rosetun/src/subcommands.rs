use std::fmt;

#[derive(PartialEq, Eq)]
pub(crate) enum SubCommand {
    Add {
        url: String,
        name: Option<String>,
        user_agent: Option<String>,
        send_hwid: bool,
    },
    Update {
        id: Option<String>,
    },
    List,
    Remove {
        id: String,
    },
}

impl fmt::Debug for SubCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add {
                url,
                name,
                user_agent,
                send_hwid,
            } => f
                .debug_struct("Add")
                .field("url", &rosetun_core::redacted_subscription_url(url))
                .field("has_name", &name.is_some())
                .field("has_user_agent", &user_agent.is_some())
                .field("send_hwid", send_hwid)
                .finish(),
            Self::Update { id } => f.debug_struct("Update").field("id", id).finish(),
            Self::List => f.write_str("List"),
            Self::Remove { id } => f.debug_struct("Remove").field("id", id).finish(),
        }
    }
}

pub(crate) fn parse(arguments: &[&str]) -> Result<SubCommand, String> {
    match arguments {
        ["add", url, flags @ ..] => parse_add(url, flags),
        ["add"] => Err("sub add requires a subscription URL".to_owned()),
        ["update"] => Ok(SubCommand::Update { id: None }),
        ["update", id] => Ok(SubCommand::Update {
            id: Some(parse_id(id)?),
        }),
        ["list"] => Ok(SubCommand::List),
        ["remove", id] => Ok(SubCommand::Remove { id: parse_id(id)? }),
        ["update", ..] => Err("sub update accepts zero or one subscription ID".to_owned()),
        ["list", ..] => Err("sub list does not accept arguments".to_owned()),
        ["remove", ..] => Err("sub remove requires exactly one subscription ID".to_owned()),
        [] => Err("sub requires add, update, list or remove".to_owned()),
        _ => Err("unknown subscription command".to_owned()),
    }
}

pub(crate) fn parse_nodes(arguments: &[&str]) -> Result<Option<String>, String> {
    match arguments {
        [] => Ok(None),
        [id] => Ok(Some(parse_id(id)?)),
        _ => Err("nodes accepts zero or one subscription ID".to_owned()),
    }
}

fn parse_id(value: &str) -> Result<String, String> {
    if value.is_empty() || value.starts_with('-') {
        return Err("a subscription ID is required, not an option".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_add(url: &str, flags: &[&str]) -> Result<SubCommand, String> {
    if url.is_empty() || url.starts_with('-') {
        return Err("sub add requires a subscription URL before its options".to_owned());
    }

    let mut name = None;
    let mut user_agent = None;
    let mut send_hwid = true;
    let mut index = 0;

    while index < flags.len() {
        match flags[index] {
            "--name" => {
                if name.is_some() {
                    return Err("--name may only be specified once".to_owned());
                }
                name = Some(option_value(flags, index, "--name")?);
                index += 2;
            }
            "--user-agent" => {
                if user_agent.is_some() {
                    return Err("--user-agent may only be specified once".to_owned());
                }
                user_agent = Some(option_value(flags, index, "--user-agent")?);
                index += 2;
            }
            "--no-hwid" => {
                if !send_hwid {
                    return Err("--no-hwid may only be specified once".to_owned());
                }
                send_hwid = false;
                index += 1;
            }
            _ => return Err("unknown option or unexpected argument for sub add".to_owned()),
        }
    }

    Ok(SubCommand::Add {
        url: url.to_owned(),
        name,
        user_agent,
        send_hwid,
    })
}

fn option_value(arguments: &[&str], index: usize, option: &'static str) -> Result<String, String> {
    arguments
        .get(index + 1)
        .filter(|value| !value.is_empty() && !value.starts_with("--"))
        .map(|value| (*value).to_owned())
        .ok_or_else(|| format!("{option} requires a non-empty value"))
}

#[cfg(test)]
mod tests {
    use super::{SubCommand, parse, parse_nodes};

    const URL: &str = "https://sub.example.com/private-token?key=query-secret";

    #[test]
    fn add_defaults_are_parsed() {
        assert_eq!(
            parse(&["add", URL]),
            Ok(SubCommand::Add {
                url: URL.to_owned(),
                name: None,
                user_agent: None,
                send_hwid: true,
            })
        );
    }

    #[test]
    fn add_flags_work_in_every_order() {
        let orders: [&[&str]; 6] = [
            &["--name", "Example", "--user-agent", "Client/1", "--no-hwid"],
            &["--name", "Example", "--no-hwid", "--user-agent", "Client/1"],
            &["--user-agent", "Client/1", "--name", "Example", "--no-hwid"],
            &["--user-agent", "Client/1", "--no-hwid", "--name", "Example"],
            &["--no-hwid", "--name", "Example", "--user-agent", "Client/1"],
            &["--no-hwid", "--user-agent", "Client/1", "--name", "Example"],
        ];

        for flags in orders {
            let mut arguments = vec!["add", URL];
            arguments.extend_from_slice(flags);
            assert_eq!(
                parse(&arguments),
                Ok(SubCommand::Add {
                    url: URL.to_owned(),
                    name: Some("Example".to_owned()),
                    user_agent: Some("Client/1".to_owned()),
                    send_hwid: false,
                })
            );
        }
    }

    #[test]
    fn remaining_subscription_commands_are_parsed() {
        assert_eq!(parse(&["update"]), Ok(SubCommand::Update { id: None }));
        assert_eq!(
            parse(&["update", "1"]),
            Ok(SubCommand::Update {
                id: Some("1".to_owned()),
            })
        );
        assert_eq!(parse(&["list"]), Ok(SubCommand::List));
        assert_eq!(
            parse(&["remove", "2"]),
            Ok(SubCommand::Remove { id: "2".to_owned() })
        );
    }

    #[test]
    fn nodes_accepts_an_optional_subscription_id() {
        assert_eq!(parse_nodes(&[]), Ok(None));
        assert_eq!(parse_nodes(&["1"]), Ok(Some("1".to_owned())));
        assert!(parse_nodes(&["1", "2"]).is_err());
        assert!(parse_nodes(&["--unknown"]).is_err());
        assert!(parse_nodes(&[""]).is_err());
    }

    #[test]
    fn invalid_subscription_arguments_are_rejected() {
        let invalid: &[&[&str]] = &[
            &[],
            &["unknown"],
            &["add"],
            &["add", ""],
            &["add", "--no-hwid"],
            &["add", URL, "--name"],
            &["add", URL, "--name", ""],
            &["add", URL, "--user-agent"],
            &["add", URL, "--name", "--no-hwid"],
            &["add", URL, "--unknown"],
            &["add", URL, "extra"],
            &["add", URL, "--no-hwid", "--no-hwid"],
            &["add", URL, "--name", "A", "--name", "B"],
            &["add", URL, "--user-agent", "A", "--user-agent", "B"],
            &["update", "1", "2"],
            &["update", "--unknown"],
            &["list", "extra"],
            &["remove"],
            &["remove", "1", "2"],
            &["remove", "--unknown"],
        ];

        for arguments in invalid {
            assert!(parse(arguments).is_err(), "accepted {arguments:?}");
        }
    }

    #[test]
    fn argument_errors_do_not_echo_secrets() {
        for arguments in [
            vec!["add", URL, URL],
            vec![URL],
            vec!["list", URL],
            vec!["update", "1", URL],
        ] {
            let error = parse(&arguments).unwrap_err();
            assert!(!error.contains("private-token"));
            assert!(!error.contains("query-secret"));
        }
    }

    #[test]
    fn add_debug_redacts_the_url_and_optional_values() {
        let command = parse(&[
            "add",
            URL,
            "--name",
            "private-name",
            "--user-agent",
            "private-agent",
        ])
        .unwrap();

        let debug = format!("{command:?}");

        assert!(debug.contains("https://sub.example.com/…"));
        for secret in [
            "private-token",
            "query-secret",
            "private-name",
            "private-agent",
        ] {
            assert!(!debug.contains(secret));
        }
    }
}
