//! Horizon's own login modes for a dedicated server, off unless
//! `horizon-auth-mode` is set: `premium` (every player passes the online
//! check), `cracked` (nobody is checked with Mojang; everyone gets the offline
//! UUID and a password) or `hybrid` (a name an account owns must pass the
//! online check, and keeps its real UUID; any other name is cracked).
//!
//! The decision is made from the name alone, before the encryption request:
//! a cracked client answers that request by disconnecting, and the UUID a
//! client sends is its own choice, so neither can tell the two apart. The
//! design follows EasyAuth (MIT, samo_lego and NikitaCartes) and FastLogin;
//! no code of theirs is used.

use super::OnlineMode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// server.properties: `premium`, `cracked`, `hybrid`, or empty / `off`.
pub const MODE_PROPERTY: &str = "horizon-auth-mode";

/// A name no account owned is looked up again after this long: names are
/// bought and changed.
const NOT_PREMIUM_FOR: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Premium,
    Cracked,
    Hybrid,
}

impl Mode {
    pub fn parse(text: &str) -> Result<Option<Mode>, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "false" => Ok(None),
            "premium" => Ok(Some(Mode::Premium)),
            "cracked" => Ok(Some(Mode::Cracked)),
            "hybrid" => Ok(Some(Mode::Hybrid)),
            other => Err(format!(
                "{MODE_PROPERTY}={other}: use premium, cracked, hybrid or off"
            )),
        }
    }
}

/// How a player with this name joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    /// Checked with Mojang: the account's own UUID and skin, no password.
    Premium,
    /// The offline UUID, protected by a password.
    Cracked,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Lookup {
    /// The account's UUID, undashed, when one owns the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    /// Seconds since the epoch.
    checked: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    /// Lower-case name to what Mojang said about it.
    #[serde(default)]
    names: BTreeMap<String, Lookup>,
    /// Lower-case names an operator lets join cracked though an account owns
    /// them (`/authallowcracked`): a password for everyone using the name.
    #[serde(default)]
    allow_cracked: BTreeSet<String>,
}

pub struct Auth {
    pub mode: Mode,
    /// The key pair the online check uses (premium and hybrid).
    pub online: Option<Arc<OnlineMode>>,
    dir: PathBuf,
    store: Mutex<Store>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Auth {
    /// The mode, with its state from `dir` (`auth/` in the server folder).
    pub fn load(mode: Mode, dir: &Path, online: Option<Arc<OnlineMode>>) -> Self {
        let store = std::fs::read_to_string(dir.join("names.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            mode,
            online,
            dir: dir.to_owned(),
            store: Mutex::new(store),
        }
    }

    fn save(&self, store: &Store) {
        let _ = std::fs::create_dir_all(&self.dir);
        if let Ok(text) = serde_json::to_string_pretty(store) {
            let path = self.dir.join("names.json");
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(tmp, path);
            }
        }
    }

    /// How `name` joins. An error when Mojang can't say whether an account
    /// owns a name it has not seen: the player is refused, never guessed
    /// cracked, which would hand a premium player's name to anyone.
    pub fn identity(&self, name: &str) -> Result<Identity, String> {
        match self.mode {
            Mode::Premium => return Ok(Identity::Premium),
            Mode::Cracked => return Ok(Identity::Cracked),
            Mode::Hybrid => {}
        }
        let key = name.to_ascii_lowercase();
        {
            let store = self.store.lock().unwrap();
            if store.allow_cracked.contains(&key) {
                return Ok(Identity::Cracked);
            }
            if let Some(seen) = store.names.get(&key)
                && (seen.account.is_some() || now() < seen.checked + NOT_PREMIUM_FOR)
            {
                return Ok(Self::of(seen));
            }
        }
        let found = crate::server::profiles::lookup_by_name(
            &crate::server::profiles::discovery_url(),
            name,
        )?;
        let seen = Lookup {
            account: found.map(|p| format!("{:032x}", p.id)),
            checked: now(),
        };
        let identity = Self::of(&seen);
        let mut store = self.store.lock().unwrap();
        store.names.insert(key, seen);
        self.save(&store);
        Ok(identity)
    }

    fn of(seen: &Lookup) -> Identity {
        if seen.account.is_some() {
            Identity::Premium
        } else {
            Identity::Cracked
        }
    }

    /// `/authallowcracked NAME` (and its undo): whether a name an account
    /// owns may join cracked, with a password.
    pub fn set_allow_cracked(&self, name: &str, allow: bool) {
        let mut store = self.store.lock().unwrap();
        let key = name.to_ascii_lowercase();
        if allow {
            store.allow_cracked.insert(key);
        } else {
            store.allow_cracked.remove(&key);
        }
        self.save(&store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_and_refuse_typos() {
        assert_eq!(Mode::parse(""), Ok(None));
        assert_eq!(Mode::parse(" Hybrid "), Ok(Some(Mode::Hybrid)));
        assert!(Mode::parse("hybird").is_err());
    }

    #[test]
    fn fixed_modes_never_ask_mojang() {
        let dir = std::env::temp_dir().join(format!("horizon-auth-{}", std::process::id()));
        let premium = Auth::load(Mode::Premium, &dir, None);
        let cracked = Auth::load(Mode::Cracked, &dir, None);
        assert_eq!(premium.identity("Notch"), Ok(Identity::Premium));
        assert_eq!(cracked.identity("Notch"), Ok(Identity::Cracked));
    }

    #[test]
    fn hybrid_uses_what_it_saw_and_operators_overrides() {
        let dir = std::env::temp_dir().join(format!("horizon-auth-h-{}", std::process::id()));
        let auth = Auth::load(Mode::Hybrid, &dir, None);
        {
            let mut store = auth.store.lock().unwrap();
            store.names.insert(
                "owned".into(),
                Lookup {
                    account: Some("0".repeat(32)),
                    checked: 0,
                },
            );
            store.names.insert(
                "free".into(),
                Lookup {
                    account: None,
                    checked: now(),
                },
            );
        }
        assert_eq!(auth.identity("Owned"), Ok(Identity::Premium));
        assert_eq!(auth.identity("FREE"), Ok(Identity::Cracked));
        auth.set_allow_cracked("owned", true);
        assert_eq!(auth.identity("owned"), Ok(Identity::Cracked));
        let _ = std::fs::remove_dir_all(dir);
    }
}
