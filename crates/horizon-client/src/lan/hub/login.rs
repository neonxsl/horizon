//! Horizon's auth on the hub: a cracked player is held as a spectator where
//! it joined until `/login` or `/register` (`super::super::auth`). Every
//! packet a player sends passes `auth_keeps` before its inbox, so a held
//! player's moves, actions, clicks, chat and other commands never reach the
//! game; only the packets that keep the connection alive do.
use super::Hub;
use crate::lan::auth::{ATTEMPTS, Hold, LOGIN_SECONDS, Outcome};
use crate::lan::guest::SPECTATOR;
use horizon_protocol::{
    packets::play::{self, Clientbound as C, Serverbound as S},
    text::literal,
};

/// What a held player says, word by word.
fn words(command: &str) -> Vec<&str> {
    command.split_whitespace().collect()
}

impl Hub {
    fn auth(&self) -> Option<std::sync::Arc<crate::lan::auth::Auth>> {
        self.lan.shared.config.auth.clone()
    }

    fn tell(&self, conn: u32, text: &str) {
        if let Some(g) = self.guest(conn) {
            g.send(&horizon_protocol::packets::play::Clientbound::SystemChat(
                horizon_protocol::packets::play::SystemChat {
                    content: literal(text),
                    overlay: false,
                },
            ));
        }
    }

    /// Once a joining player's saved state is applied: hold a cracked one
    /// unless its address logged in as it within the session time.
    pub fn auth_begin(&mut self, conn: u32) {
        let Some(auth) = self.auth() else {
            return;
        };
        let ticks = self.ticks;
        let Some(g) = self.guest_mut(conn) else {
            return;
        };
        if !g.cracked {
            return;
        }
        let (name, ip) = (g.name.clone(), g.address.ip());
        if auth.accounts.session(&name, ip) {
            self.tell(conn, "[Auth] Logged in: you joined from the same address.");
            return;
        }
        g.auth_hold = Some(Hold {
            game_mode: g.game_mode,
            flying: g.flying,
            position: g.position,
            since: ticks,
            attempts: 0,
            checking: false,
            moved: false,
        });
        // A spectator here, so nothing hurts it and mobs ignore it; its client
        // is told adventure with no walking speed, so it keeps collisions
        // (no flying through the ground to see what's under it) and stands.
        g.game_mode = SPECTATOR;
        g.flying = false;
        g.send(&C::GameEvent(play::GameEvent {
            event: super::game_event::CHANGE_GAME_MODE,
            param: 2.0,
        }));
        g.send(&C::PlayerAbilities(play::PlayerAbilities {
            flags: 1,
            flying_speed: 0.0,
            walking_speed: 0.0,
        }));
        self.remind(conn);
    }

    fn remind(&self, conn: u32) {
        let Some(auth) = self.auth() else {
            return;
        };
        let Some(g) = self.guest(conn) else {
            return;
        };
        if auth.accounts.registered(&g.name) {
            self.tell(conn, "[Auth] Log in with /login <password>");
        } else {
            self.tell(conn, "[Auth] Register with /register <password> <password>");
        }
    }

    /// Whether this packet goes on to the game. Held players keep only the
    /// connection's own traffic; their `/login` and `/register` are answered
    /// here, and anyone's `/changepassword`.
    pub fn auth_keeps(&mut self, conn: u32, packet: &S) -> bool {
        let Some(auth) = self.auth() else {
            return true;
        };
        let Some(g) = self.guest(conn) else {
            return true;
        };
        let command = match packet {
            S::ChatCommand(c) => Some(c.command.as_str()),
            S::ChatCommandSigned(c) => Some(c.command.as_str()),
            _ => None,
        };
        let held = g.auth_hold.is_some();
        let (name, ip) = (g.name.clone(), g.address.ip());
        // Operators' auth and proxy commands (crate::lan::admin).
        if let Some(command) = command
            && !held
            && g.permission >= 3
            && let Some(lines) = crate::lan::admin::run(&self.lan.shared.config, command)
        {
            for line in lines {
                self.tell(conn, &line);
            }
            return false;
        }
        if let Some(command) = command {
            let w = words(command);
            match w.first().map(|s| s.to_ascii_lowercase()).as_deref() {
                Some("login" | "l" | "register" | "reg" | "changepassword") if !g.cracked => {
                    self.tell(
                        conn,
                        "[Auth] You joined with your Minecraft account: no password needed.",
                    );
                    return false;
                }
                Some("changepassword") if g.cracked && !held => {
                    if let [_, old, new] = w[..] {
                        auth.accounts
                            .start_change(conn, &name, old.to_owned(), new.to_owned());
                    } else {
                        self.tell(conn, "[Auth] /changepassword <old> <new>");
                    }
                    return false;
                }
                Some("login" | "l" | "register" | "reg") if g.cracked && !held => {
                    self.tell(conn, "[Auth] You're already logged in.");
                    return false;
                }
                Some("login" | "l") if held => {
                    if self
                        .guest(conn)
                        .is_some_and(|g| g.auth_hold.as_ref().is_some_and(|h| h.checking))
                    {
                        return false;
                    }
                    match w[..] {
                        [_, password] if auth.accounts.registered(&name) => {
                            self.set_checking(conn, true);
                            auth.accounts
                                .start_login(conn, &name, password.to_owned(), ip);
                        }
                        [_, _] => self.tell(
                            conn,
                            "[Auth] Register first: /register <password> <password>",
                        ),
                        _ => self.tell(conn, "[Auth] /login <password>"),
                    }
                    return false;
                }
                Some("register" | "reg") if held => {
                    if self
                        .guest(conn)
                        .is_some_and(|g| g.auth_hold.as_ref().is_some_and(|h| h.checking))
                    {
                        return false;
                    }
                    match w[..] {
                        _ if auth.accounts.registered(&name) => {
                            self.tell(conn, "[Auth] Already registered: /login <password>");
                        }
                        [_, a, b] if a != b => self.tell(conn, "[Auth] The passwords differ."),
                        [_, a, _] if a.len() < 4 => {
                            self.tell(conn, "[Auth] Use at least 4 characters.");
                        }
                        [_, a, _] => {
                            self.set_checking(conn, true);
                            auth.accounts.start_register(conn, &name, a.to_owned(), ip);
                        }
                        _ => self.tell(conn, "[Auth] /register <password> <password>"),
                    }
                    return false;
                }
                _ => {}
            }
        }
        if !held {
            return true;
        }
        if matches!(
            packet,
            S::MovePlayerPos(_) | S::MovePlayerPosRot(_) | S::MoveVehicle(_)
        ) && let Some(h) = self.guest_mut(conn).and_then(|g| g.auth_hold.as_mut())
        {
            h.moved = true;
        }
        matches!(
            packet,
            S::AcceptTeleportation(_)
                | S::ChatAck(_)
                | S::ChatSessionUpdate(_)
                | S::ChunkBatchReceived(_)
                | S::ClientInformation(_)
                | S::ClientTickEnd(_)
                | S::CookieResponse(_)
                | S::CustomPayload(_)
                | S::KeepAlive(_)
                | S::PingRequest(_)
                | S::PlayerLoaded(_)
                | S::Pong(_)
                | S::ResourcePack(_)
        )
    }

    fn set_checking(&mut self, conn: u32, checking: bool) {
        if let Some(h) = self.guest_mut(conn).and_then(|g| g.auth_hold.as_mut()) {
            h.checking = checking;
        }
    }

    /// Lets a held player go: its own game mode, where it was held.
    fn release(&mut self, conn: u32) {
        let Some(hold) = self.guest_mut(conn).and_then(|g| g.auth_hold.take()) else {
            return;
        };
        self.set_game_mode(conn, hold.game_mode);
        if let Some(g) = self.guest_mut(conn) {
            g.flying = hold.flying;
        }
        if let Some(i) = self.guests.iter().position(|g| g.conn == conn) {
            self.teleport(i, Some(hold.position));
        }
    }

    /// Once a tick: finished password checks, then the held players'
    /// reminders, time limit and place.
    pub fn auth_tick(&mut self) {
        let Some(auth) = self.auth() else {
            return;
        };
        for (conn, _, outcome) in auth.accounts.finished() {
            self.set_checking(conn, false);
            match outcome {
                Outcome::LoggedIn => {
                    self.release(conn);
                    self.tell(conn, "[Auth] Logged in.");
                }
                Outcome::Registered => {
                    self.release(conn);
                    self.tell(conn, "[Auth] Registered and logged in.");
                }
                Outcome::Wrong => {
                    let attempts =
                        self.guest_mut(conn)
                            .and_then(|g| g.auth_hold.as_mut())
                            .map(|h| {
                                h.attempts += 1;
                                h.attempts
                            });
                    if attempts.is_some_and(|a| a >= ATTEMPTS) {
                        self.kick(conn, literal("Too many wrong passwords."));
                    } else {
                        self.tell(conn, "[Auth] Wrong password.");
                    }
                }
                Outcome::Changed => self.tell(conn, "[Auth] Password changed."),
                Outcome::ChangeWrong => self.tell(conn, "[Auth] Your old password is wrong."),
                Outcome::Failed(why) => self.tell(conn, &format!("[Auth] That didn't work: {why}")),
            }
        }
        // Every tick, a held player whose client moved goes straight back.
        let moved: Vec<(usize, [f64; 3])> = self
            .guests
            .iter_mut()
            .enumerate()
            .filter_map(|(i, g)| {
                let h = g.auth_hold.as_mut().filter(|h| h.moved)?;
                h.moved = false;
                Some((i, h.position))
            })
            .collect();
        for (i, position) in moved {
            self.teleport(i, Some(position));
        }
        if !self.ticks.is_multiple_of(20) {
            return;
        }
        let ticks = self.ticks;
        let held: Vec<(usize, u32, Hold)> = self
            .guests
            .iter()
            .enumerate()
            .filter(|(_, g)| g.left_reason.is_empty())
            .filter_map(|(i, g)| Some((i, g.conn, g.auth_hold.clone()?)))
            .collect();
        for (i, conn, hold) in held {
            let waited = (ticks - hold.since) / 20;
            if waited >= LOGIN_SECONDS {
                self.kick(conn, literal("You took too long to log in."));
                continue;
            }
            // Its client moved it; the server never did.
            self.teleport(i, Some(hold.position));
            if waited.is_multiple_of(10) {
                self.remind(conn);
            }
        }
    }
}
