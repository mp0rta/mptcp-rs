//! The scenario driver (M3 spec §5.3): the client's path-management policy, as a script. It
//! sees the connection's events and time and says which actions are due; `main` runs them.
//!
//! One directive per line (`#` starts a comment):
//! - `at <barrier> +<ms> <action>`: `<ms>` after the barrier event first happens. Barriers:
//!   `Connected`, `SubflowUp:<n>`, `AddressAnnounced:<id>`, `SubflowDown:<n>`.
//! - `after <label> +<ms> <action>`: `<ms>` after the action labelled `<label>` ran.
//! - `on announced join <local>`: each announced address is joined from `<local>`, unless a
//!   subflow from `<local>` to it is open (a repeated announcement).
//! - `on down-transient rejoin +<ms>`: a subflow reset with a transient MP_TCPRST is joined
//!   again from the same local IP to the same remote, `<ms>` later.
//!
//! Actions: `join <local> <remote> [backup] [mtu <n>]`, `set-backup <n> on|off`,
//! `set-local-backup <n> on|off`, `close-subflow <n>`, `remove-address <ip>`, `abort`; each may
//! carry `label=<name>`. Subflow `<n>` is `SubflowId(<n>)`: 0 is the initial subflow, then the
//! joins in the order they were made. Reactions stop for good once the application closes or
//! aborts, or the connection falls back or closes.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Join {
        local: IpAddr,
        remote: SocketAddr,
        backup: bool,
        mtu: Option<u16>,
    },
    SetBackup(usize, bool),
    SetLocalBackup(usize, bool),
    CloseSubflow(usize),
    RemoveAddress(IpAddr),
    Abort,
    /// Join again from subflow `n`'s local IP to its remote.
    Rejoin(usize),
    /// `on announced join`: join `remote` from `local` unless a subflow between them is open.
    JoinAnnounced(IpAddr, SocketAddr),
}

/// What the driver reacts to; subflows by number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ev {
    Connected,
    Up(usize),
    Down {
        sub: usize,
        transient: bool,
    },
    Announced {
        id: u8,
        addr: SocketAddr,
    },
    /// `close` or `abort` was called, or the connection fell back or closed.
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Trigger {
    Connected,
    Up(usize),
    Announced(u8),
    Down(usize),
    After(String),
}

struct Directive {
    text: String,
    trigger: Trigger,
    delay: Duration,
    action: Action,
    label: Option<String>,
    /// Armed: due at this time.
    at: Option<Duration>,
    done: bool,
}

#[derive(Default)]
pub struct Script {
    directives: Vec<Directive>,
    join_announced: Option<IpAddr>,
    rejoin: Option<Duration>,
    /// Due reactions, in the order they arose.
    reactions: Vec<(Duration, Action)>,
    stopped: bool,
}

fn ms(t: &str) -> Option<Duration> {
    Some(Duration::from_millis(t.strip_prefix('+')?.parse().ok()?))
}

fn on_off(t: &str) -> Option<bool> {
    match t {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// An action and its label.
fn action(tokens: &[&str]) -> Option<(Action, Option<String>)> {
    let label = (tokens.iter()).find_map(|t| t.strip_prefix("label=").map(String::from));
    let t: Vec<&str> = (tokens.iter().copied())
        .filter(|t| !t.starts_with("label="))
        .collect();
    let a = match t[..] {
        ["join", local, remote, ref rest @ ..] => {
            let (mut backup, mut mtu) = (false, None);
            let mut rest = rest.iter();
            while let Some(&w) = rest.next() {
                match w {
                    "backup" => backup = true,
                    "mtu" => mtu = Some(rest.next()?.parse().ok()?),
                    _ => return None,
                }
            }
            Action::Join {
                local: local.parse().ok()?,
                remote: remote.parse().ok()?,
                backup,
                mtu,
            }
        }
        ["set-backup", n, v] => Action::SetBackup(n.parse().ok()?, on_off(v)?),
        ["set-local-backup", n, v] => Action::SetLocalBackup(n.parse().ok()?, on_off(v)?),
        ["close-subflow", n] => Action::CloseSubflow(n.parse().ok()?),
        ["remove-address", ip] => Action::RemoveAddress(ip.parse().ok()?),
        ["abort"] => Action::Abort,
        _ => return None,
    };
    Some((a, label))
}

fn barrier(t: &str) -> Option<Trigger> {
    let (name, n) = t.split_once(':').map_or((t, None), |(a, b)| (a, Some(b)));
    Some(match (name, n) {
        ("Connected", None) => Trigger::Connected,
        ("SubflowUp", Some(n)) => Trigger::Up(n.parse().ok()?),
        ("AddressAnnounced", Some(n)) => Trigger::Announced(n.parse().ok()?),
        ("SubflowDown", Some(n)) => Trigger::Down(n.parse().ok()?),
        _ => return None,
    })
}

impl Script {
    pub fn parse(text: &str) -> Result<Script, String> {
        let mut s = Script::default();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap().trim();
            let t: Vec<&str> = line.split_whitespace().collect();
            let bad = || format!("script line {}: {line}", i + 1);
            let (trigger, delay, rest) = match t[..] {
                [] => continue,
                ["on", "announced", "join", local] => {
                    s.join_announced = Some(local.parse().map_err(|_| bad())?);
                    continue;
                }
                ["on", "down-transient", "rejoin", d] => {
                    s.rejoin = Some(ms(d).ok_or_else(bad)?);
                    continue;
                }
                ["at", b, d, ref rest @ ..] => (barrier(b), ms(d), rest),
                ["after", label, d, ref rest @ ..] => {
                    (Some(Trigger::After(label.into())), ms(d), rest)
                }
                _ => return Err(bad()),
            };
            let (Some(trigger), Some(delay), Some((action, label))) =
                (trigger, delay, action(rest))
            else {
                return Err(bad());
            };
            s.directives.push(Directive {
                text: line.into(),
                trigger,
                delay,
                action,
                label,
                at: None,
                done: false,
            });
        }
        Ok(s)
    }

    /// Arms the directives whose barrier `ev` is (its first occurrence) and makes reactions
    /// due.
    pub fn on_event(&mut self, ev: Ev, now: Duration) {
        let trigger = match ev {
            Ev::Connected => Trigger::Connected,
            Ev::Up(n) => Trigger::Up(n),
            Ev::Down { sub, .. } => Trigger::Down(sub),
            Ev::Announced { id, .. } => Trigger::Announced(id),
            Ev::Stop => {
                self.stopped = true;
                self.reactions.clear();
                return;
            }
        };
        self.arm(&trigger, now);
        if self.stopped {
            return;
        }
        match ev {
            Ev::Announced { addr, .. } => {
                if let Some(local) = self.join_announced {
                    self.reactions
                        .push((now, Action::JoinAnnounced(local, addr)));
                }
            }
            Ev::Down {
                sub,
                transient: true,
            } => {
                if let Some(d) = self.rejoin {
                    self.reactions.push((now + d, Action::Rejoin(sub)));
                }
            }
            _ => {}
        }
    }

    fn arm(&mut self, trigger: &Trigger, now: Duration) {
        for d in &mut self.directives {
            if d.at.is_none() && !d.done && d.trigger == *trigger {
                d.at = Some(now + d.delay);
            }
        }
    }

    /// The earliest time an action is due.
    pub fn next_deadline(&self) -> Option<Duration> {
        let directives = self.directives.iter().filter(|d| !d.done);
        (directives.filter_map(|d| d.at))
            .chain(self.reactions.iter().map(|r| r.0))
            .min()
    }

    /// The actions due at `now`, earliest first; each directive runs once, and an action with
    /// a label arms the `after` directives that wait for it.
    pub fn due(&mut self, now: Duration) -> Vec<Action> {
        let mut out = Vec::new();
        loop {
            let next = (self.directives.iter().enumerate())
                .filter(|(_, d)| !d.done && d.at.is_some_and(|t| t <= now))
                .min_by_key(|(_, d)| d.at)
                .map(|(i, _)| i);
            let Some(i) = next else {
                break;
            };
            let d = &mut self.directives[i];
            d.done = true;
            out.push(d.action.clone());
            if let Some(label) = d.label.clone() {
                self.arm(&Trigger::After(label), now);
            }
        }
        let (due, later) = (self.reactions.drain(..)).partition(|r| r.0 <= now);
        self.reactions = later;
        out.extend(due.into_iter().map(|r: (Duration, Action)| r.1));
        out
    }

    /// The first directive that has not run.
    pub fn unmet(&self) -> Option<&str> {
        let d = self.directives.iter().find(|d| !d.done)?;
        Some(&d.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn script_parses_every_form() {
        let text = "\
            # comment\n\
            at Connected +0 join 10.0.92.2 10.0.1.2:5201 backup mtu 1280 label=j\n\
            after j +0 set-local-backup 1 on\n\
            at SubflowUp:1 +1000 set-backup 1 off\n\
            at AddressAnnounced:2 +5 close-subflow 1\n\
            at SubflowDown:1 +0 remove-address 10.0.92.2\n\
            at Connected +2000 abort\n\
            on announced join 10.0.93.2\n\
            on down-transient rejoin +500\n";
        let sc = Script::parse(text).unwrap();
        let actions: Vec<_> = sc.directives.iter().map(|d| d.action.clone()).collect();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(
            actions,
            [
                Action::Join {
                    local: ip("10.0.92.2"),
                    remote: "10.0.1.2:5201".parse().unwrap(),
                    backup: true,
                    mtu: Some(1280)
                },
                Action::SetLocalBackup(1, true),
                Action::SetBackup(1, false),
                Action::CloseSubflow(1),
                Action::RemoveAddress(ip("10.0.92.2")),
                Action::Abort,
            ]
        );
        assert_eq!(sc.directives[0].label.as_deref(), Some("j"));
        assert_eq!(sc.directives[3].trigger, Trigger::Announced(2));
        assert_eq!(
            (sc.join_announced, sc.rejoin),
            (Some(ip("10.0.93.2")), Some(s(500)))
        );
        for bad in [
            "at Connected 0 abort",
            "at SubflowUp +0 abort",
            "at Connected +0 set-backup 1 maybe",
            "at Connected +0 join 10.0.92.2",
            "after +0 abort",
            "on down-transient rejoin 5",
            "bogus",
        ] {
            assert!(Script::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn script_barrier_after_event() {
        let mut sc = Script::parse(
            "at SubflowUp:1 +500 set-backup 1 on label=b\n\
             after b +100 abort\n",
        )
        .unwrap();
        assert_eq!((sc.due(s(10_000)), sc.next_deadline()), (vec![], None));
        sc.on_event(Ev::Up(2), s(1000));
        sc.on_event(Ev::Connected, s(1000));
        assert_eq!(sc.next_deadline(), None, "not this barrier");
        sc.on_event(Ev::Up(1), s(2000));
        sc.on_event(Ev::Up(1), s(2300)); // only the first occurrence counts
        assert_eq!(sc.next_deadline(), Some(s(2500)));
        assert_eq!(sc.due(s(2499)), vec![]);
        // Run late: the follower counts from when its leader ran.
        assert_eq!(sc.due(s(2600)), vec![Action::SetBackup(1, true)]);
        assert_eq!(sc.next_deadline(), Some(s(2700)));
        assert_eq!(sc.due(s(2700)), vec![Action::Abort]);
        assert_eq!((sc.due(s(9000)), sc.next_deadline()), (vec![], None));
        assert_eq!(sc.unmet(), None);
        // A +0 follower runs in the same step.
        let mut sc =
            Script::parse("at Connected +0 abort label=a\nafter a +0 close-subflow 0").unwrap();
        sc.on_event(Ev::Connected, s(5));
        assert_eq!(sc.due(s(5)), vec![Action::Abort, Action::CloseSubflow(0)]);
    }

    #[test]
    fn script_unmet_action_fails() {
        let mut sc = Script::parse(
            "at Connected +0 set-backup 0 on\n\
             at SubflowUp:2 +0 abort\n\
             after never +0 close-subflow 1\n",
        )
        .unwrap();
        assert_eq!(sc.unmet(), Some("at Connected +0 set-backup 0 on"));
        sc.on_event(Ev::Connected, s(1));
        sc.due(s(1));
        assert_eq!(
            sc.unmet(),
            Some("at SubflowUp:2 +0 abort"),
            "barrier never reached"
        );
        sc.on_event(Ev::Up(2), s(2));
        // Armed but its time never came.
        assert_eq!(sc.unmet(), Some("at SubflowUp:2 +0 abort"));
        sc.due(s(2));
        assert_eq!(sc.unmet(), Some("after never +0 close-subflow 1"));
    }

    #[test]
    fn script_rejoin_suppressed_after_close() {
        let mut sc =
            Script::parse("on down-transient rejoin +1000\non announced join 10.0.93.2").unwrap();
        // A transient reset rejoins after the delay; a non-transient one does not.
        sc.on_event(
            Ev::Down {
                sub: 1,
                transient: false,
            },
            s(0),
        );
        sc.on_event(
            Ev::Down {
                sub: 2,
                transient: true,
            },
            s(0),
        );
        assert_eq!(sc.next_deadline(), Some(s(1000)));
        assert_eq!(sc.due(s(1000)), vec![Action::Rejoin(2)]);
        // A pending rejoin is cancelled by the close ...
        sc.on_event(
            Ev::Down {
                sub: 3,
                transient: true,
            },
            s(2000),
        );
        sc.on_event(Ev::Stop, s(2500));
        assert_eq!((sc.due(s(3000)), sc.next_deadline()), (vec![], None));
        // ... and the R18 strand reset during the close (0x04, T=1) rejoins nothing, nor does
        // an announcement.
        sc.on_event(
            Ev::Down {
                sub: 0,
                transient: true,
            },
            s(4000),
        );
        let addr = "10.0.3.2:5201".parse().unwrap();
        sc.on_event(Ev::Announced { id: 3, addr }, s(4000));
        assert_eq!((sc.due(s(9000)), sc.next_deadline()), (vec![], None));
    }

    #[test]
    fn script_announced_join_reaction() {
        let mut sc = Script::parse("on announced join 10.0.93.2").unwrap();
        let addr = "10.0.3.2:5201".parse().unwrap();
        sc.on_event(Ev::Announced { id: 3, addr }, s(7));
        let join = Action::JoinAnnounced("10.0.93.2".parse().unwrap(), addr);
        assert_eq!(sc.due(s(7)), vec![join]);
    }
}
