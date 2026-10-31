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
    /// `/n-whitelist`: names, not UUIDs, so one entry admits a name whether
    /// it joins premium or cracked.
    #[serde(default)]
    whitelist_on: bool,
    #[serde(default)]
    whitelist: BTreeSet<String>,
}

pub struct Auth {
    pub mode: Mode,
    /// The key pair the online check uses (premium and hybrid).
    pub online: Option<Arc<OnlineMode>>,
    /// The cracked players' passwords.
    pub accounts: Arc<Accounts>,
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
    pub fn load(
        mode: Mode,
        dir: &Path,
        online: Option<Arc<OnlineMode>>,
        session_hours: u64,
    ) -> Self {
        let store = std::fs::read_to_string(dir.join("names.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            mode,
            online,
            accounts: Arc::new(Accounts::load(dir, session_hours)),
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
        // Mojang's API is slow now and then: one more try before refusing.
        let discovery = crate::server::profiles::discovery_url();
        let found = crate::server::profiles::lookup_by_name(&discovery, name)
            .or_else(|_| crate::server::profiles::lookup_by_name(&discovery, name))?;
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

    /// The name whitelist refuses this name.
    pub fn whitelist_refuses(&self, name: &str) -> bool {
        let store = self.store.lock().unwrap();
        store.whitelist_on && !store.whitelist.contains(&name.to_ascii_lowercase())
    }

    /// `/n-whitelist ...`: what to tell the one who ran it.
    pub fn whitelist_command(&self, args: &[&str]) -> String {
        let mut store = self.store.lock().unwrap();
        let reply = match args {
            ["on"] => {
                store.whitelist_on = true;
                "The name whitelist is on.".to_owned()
            }
            ["off"] => {
                store.whitelist_on = false;
                "The name whitelist is off.".to_owned()
            }
            ["add", name] => {
                if store.whitelist.insert(name.to_ascii_lowercase()) {
                    format!("Added {name} to the name whitelist.")
                } else {
                    format!("{name} is already on the name whitelist.")
                }
            }
            ["remove", name] => {
                if store.whitelist.remove(&name.to_ascii_lowercase()) {
                    format!("Removed {name} from the name whitelist.")
                } else {
                    format!("{name} is not on the name whitelist.")
                }
            }
            ["list"] => {
                let names: Vec<&str> = store.whitelist.iter().map(String::as_str).collect();
                format!(
                    "The name whitelist is {} and has {} names: {}",
                    if store.whitelist_on { "on" } else { "off" },
                    names.len(),
                    names.join(", ")
                )
            }
            _ => return "/n-whitelist on | off | add <name> | remove <name> | list".to_owned(),
        };
        self.save(&store);
        reply
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

/// Seconds a cracked player has to log in.
pub const LOGIN_SECONDS: u64 = 60;
/// Wrong passwords before the kick.
pub const ATTEMPTS: u8 = 3;
/// server.properties: hours a cracked player's last address logs it in
/// without its password (0 turns it off).
pub const SESSION_PROPERTY: &str = "horizon-auth-session-hours";

/// A cracked player not logged in yet: a spectator where it joined, its own
/// game mode put back once it logs in (or saved as it was if it leaves).
#[derive(Clone, Debug)]
pub struct Hold {
    pub game_mode: i32,
    pub flying: bool,
    pub position: [f64; 3],
    /// Hub tick it joined.
    pub since: u64,
    pub attempts: u8,
    /// A password check runs on another thread.
    pub checking: bool,
    /// Its client sent a move since the last tick: put it back this tick.
    pub moved: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Account {
    /// argon2id, PHC string.
    hash: String,
    /// The address of the last login, and when (seconds since the epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(default)]
    login: u64,
}

/// What a password check on another thread found, for the hub to act on.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    LoggedIn,
    Registered,
    Wrong,
    Changed,
    ChangeWrong,
    Failed(String),
}

/// The cracked players' passwords (`auth/accounts.json`) and the checks in
/// flight. Hashing takes tens of milliseconds, so it never runs on the
/// server thread.
#[derive(Default)]
pub struct Accounts {
    path: PathBuf,
    session_secs: u64,
    list: Mutex<BTreeMap<String, Account>>,
    done: Mutex<Vec<(u32, String, Outcome)>>,
}

fn hash(password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

fn matches(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(hash).is_ok_and(|h| {
        argon2::Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

impl Accounts {
    pub fn load(dir: &Path, session_hours: u64) -> Self {
        let path = dir.join("accounts.json");
        let list = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path,
            session_secs: session_hours * 3600,
            list: Mutex::new(list),
            done: Mutex::default(),
        }
    }

    fn save(&self, list: &BTreeMap<String, Account>) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string_pretty(list) {
            let tmp = self.path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    pub fn registered(&self, name: &str) -> bool {
        self.list
            .lock()
            .unwrap()
            .contains_key(&name.to_ascii_lowercase())
    }

    /// The name last logged in from `ip`, within the session time.
    pub fn session(&self, name: &str, ip: std::net::IpAddr) -> bool {
        let list = self.list.lock().unwrap();
        self.session_secs > 0
            && list.get(&name.to_ascii_lowercase()).is_some_and(|a| {
                a.ip.as_deref() == Some(ip.to_string().as_str())
                    && now() < a.login + self.session_secs
            })
    }

    fn remember(&self, name: &str, ip: std::net::IpAddr) {
        let mut list = self.list.lock().unwrap();
        if let Some(a) = list.get_mut(&name.to_ascii_lowercase()) {
            a.ip = Some(ip.to_string());
            a.login = now();
        }
        self.save(&list);
    }

    /// `/authreset`: the name registers again on its next join.
    pub fn reset(&self, name: &str) -> bool {
        let mut list = self.list.lock().unwrap();
        let had = list.remove(&name.to_ascii_lowercase()).is_some();
        self.save(&list);
        had
    }

    /// Outcomes of finished checks: the connection, the name and what happened.
    pub fn finished(&self) -> Vec<(u32, String, Outcome)> {
        std::mem::take(&mut *self.done.lock().unwrap())
    }

    fn run(
        self: &Arc<Self>,
        conn: u32,
        name: &str,
        job: impl FnOnce(&Self) -> Outcome + Send + 'static,
    ) {
        let me = self.clone();
        let name = name.to_owned();
        let spawned = std::thread::Builder::new()
            .name("Horizon auth".into())
            .spawn(move || {
                let outcome = job(&me);
                me.done.lock().unwrap().push((conn, name, outcome));
            });
        if spawned.is_err() {
            self.done.lock().unwrap().push((
                conn,
                String::new(),
                Outcome::Failed("could not start the check".into()),
            ));
        }
    }

    pub fn start_login(
        self: &Arc<Self>,
        conn: u32,
        name: &str,
        password: String,
        ip: std::net::IpAddr,
    ) {
        let key = name.to_ascii_lowercase();
        let n = name.to_owned();
        self.run(conn, name, move |me| {
            let hash = me.list.lock().unwrap().get(&key).map(|a| a.hash.clone());
            match hash {
                Some(h) if matches(&password, &h) => {
                    me.remember(&n, ip);
                    Outcome::LoggedIn
                }
                Some(_) => Outcome::Wrong,
                None => Outcome::Failed("not registered".into()),
            }
        });
    }

    pub fn start_register(
        self: &Arc<Self>,
        conn: u32,
        name: &str,
        password: String,
        ip: std::net::IpAddr,
    ) {
        let key = name.to_ascii_lowercase();
        self.run(conn, name, move |me| match hash(&password) {
            Ok(hash) => {
                let mut list = me.list.lock().unwrap();
                if list.contains_key(&key) {
                    return Outcome::Failed("already registered".into());
                }
                list.insert(
                    key,
                    Account {
                        hash,
                        ip: Some(ip.to_string()),
                        login: now(),
                    },
                );
                me.save(&list);
                Outcome::Registered
            }
            Err(e) => Outcome::Failed(e),
        });
    }

    pub fn start_change(self: &Arc<Self>, conn: u32, name: &str, old: String, new: String) {
        let key = name.to_ascii_lowercase();
        self.run(conn, name, move |me| {
            let current = me.list.lock().unwrap().get(&key).map(|a| a.hash.clone());
            match current {
                Some(h) if matches(&old, &h) => match hash(&new) {
                    Ok(hash) => {
                        let mut list = me.list.lock().unwrap();
                        if let Some(a) = list.get_mut(&key) {
                            a.hash = hash;
                        }
                        me.save(&list);
                        Outcome::Changed
                    }
                    Err(e) => Outcome::Failed(e),
                },
                Some(_) => Outcome::ChangeWrong,
                None => Outcome::Failed("not registered".into()),
            }
        });
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
        let premium = Auth::load(Mode::Premium, &dir, None, 24);
        let cracked = Auth::load(Mode::Cracked, &dir, None, 24);
        assert_eq!(premium.identity("Notch"), Ok(Identity::Premium));
        assert_eq!(cracked.identity("Notch"), Ok(Identity::Cracked));
    }

    #[test]
    fn hybrid_uses_what_it_saw_and_operators_overrides() {
        let dir = std::env::temp_dir().join(format!("horizon-auth-h-{}", std::process::id()));
        let auth = Auth::load(Mode::Hybrid, &dir, None, 24);
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
