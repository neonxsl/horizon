//! Horizon's own operator commands for its auth and PROXY protocol, the same
//! from the server console and from an operator's chat (level 3 and up):
//! `/authreset`, `/authallowcracked`, `/n-whitelist` and `/proxy`.
use super::NetConfig;
use std::sync::atomic::Ordering;

/// The command's reply lines, or None when `line` is none of these commands.
pub fn run(config: &NetConfig, line: &str) -> Option<Vec<String>> {
    let line = line.strip_prefix('/').unwrap_or(line);
    let words: Vec<&str> = line.split_whitespace().collect();
    let (command, args) = words.split_first()?;
    let command = command.to_ascii_lowercase();
    let off = || vec!["Horizon auth is off: set horizon-auth-mode first.".to_owned()];
    let reply = match command.as_str() {
        "authreset" => match (config.auth.as_ref(), args) {
            (None, _) => off(),
            (Some(auth), [name]) => vec![if auth.accounts.reset(name) {
                format!("{name}'s password is removed: they register again on their next join.")
            } else {
                format!("{name} has no password.")
            }],
            _ => vec!["/authreset <name>".to_owned()],
        },
        "authallowcracked" => match (config.auth.as_ref(), args) {
            (None, _) => off(),
            (Some(auth), [name]) => {
                auth.set_allow_cracked(name, true);
                vec![format!(
                    "{name} joins cracked from now on, with a password, even with the account's own launcher."
                )]
            }
            (Some(auth), [name, "off"]) => {
                auth.set_allow_cracked(name, false);
                vec![format!(
                    "{name} is premium-only again if an account owns it."
                )]
            }
            _ => vec!["/authallowcracked <name> [off]".to_owned()],
        },
        "n-whitelist" => match config.auth.as_ref() {
            None => off(),
            Some(auth) => vec![auth.whitelist_command(args)],
        },
        "proxy" => match (config.proxy.as_ref(), args) {
            (None, _) => vec!["PROXY protocol isn't available here.".to_owned()],
            (Some(p), ["on"]) => {
                p.on.store(true, Ordering::Relaxed);
                vec![
                    "PROXY protocol is on until the server stops: only the proxy and the direct list can connect.".to_owned(),
                    "Set horizon-proxy-protocol = true in server.toml to keep it.".to_owned(),
                ]
            }
            (Some(p), ["off"]) => {
                p.on.store(false, Ordering::Relaxed);
                vec![
                    "PROXY protocol is off until the server stops: anyone connects directly."
                        .to_owned(),
                ]
            }
            (Some(p), [] | ["status"]) => {
                let list = |r: &[super::proxy::Range]| {
                    if r.is_empty() {
                        "none".to_owned()
                    } else {
                        r.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                };
                vec![
                    format!(
                        "PROXY protocol v2 is {}.",
                        if p.is_on() { "on" } else { "off" }
                    ),
                    format!("Proxy (headers believed): {}", list(&p.trusted)),
                    format!("Direct connections allowed: {}", list(&p.direct)),
                ]
            }
            _ => vec!["/proxy on | off | status".to_owned()],
        },
        _ => return None,
    };
    Some(reply)
}
