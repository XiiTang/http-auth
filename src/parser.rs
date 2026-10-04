// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parses as in [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235).
//!
//! Most callers don't need to directly parse; see [`crate::PasswordClient`] instead.

// State machine implementation of challenge parsing with a state machine.
// Nice qualities: predictable performance (no backtracking), low dependencies.
//
// The implementation is *not* a straightforward translation of the ABNF
// grammar, so we verify correctness via a fuzz tester that compares with a
// nom-based parser. See `fuzz/fuzz_targets/parse_challenges.rs`.

use std::{fmt::Display, ops::Range};

use crate::{ChallengeRef, ParamValue};

use crate::{char_classes, C_ESCAPABLE, C_OWS, C_QDTEXT, C_TCHAR};

/// Calls `log::trace!` only if the `trace` cargo feature is enabled.
macro_rules! trace {
    ($($arg:tt)+) => (#[cfg(feature = "trace")] log::trace!($($arg)+))
}

/// Parses a list of challenges as in [RFC
/// 7235](https://datatracker.ietf.org/doc/html/rfc7235) `Proxy-Authenticate`
/// or `WWW-Authenticate` header values.
///
/// Most callers don't need to directly parse; see [`crate::PasswordClient`] instead.
///
/// This is an iterator that parses lazily, returning each challenge as soon as
/// its end has been found. (Due to the grammar's ambiguous use of commas to
/// separate both challenges and parameters, a challenge's end is found after
/// parsing the *following* challenge's scheme name.) On encountering a syntax
/// error, it yields `Some(Err(_))` and fuses: all subsequent calls to
/// [`Iterator::next`] will return `None`.
///
/// See also the [`crate::parse_challenges`] convenience wrapper.
///
/// ## Example
///
/// ```rust
/// use http_auth::{parser::ChallengeParser, ChallengeRef, ParamValue};
/// let challenges = "UnsupportedSchemeA, Basic realm=\"foo\", error error error";
/// let mut parser = ChallengeParser::new(challenges);
/// let c = parser.next().unwrap().unwrap();
/// assert_eq!(c, ChallengeRef {
///     scheme: "UnsupportedSchemeA",
///     params: vec![],
///     token68: None,
/// });
/// let c = parser.next().unwrap().unwrap();
/// assert_eq!(c, ChallengeRef {
///     scheme: "Basic",
///     params: vec![("realm", ParamValue::try_from_escaped("foo").unwrap())],
///     token68: None,
/// });
/// let c = parser.next().unwrap().unwrap_err();
/// ```
///
/// ## Implementation notes
///
/// This rigorously matches the official ABNF grammar except as follows:
///
/// *   Doesn't allow non-ASCII characters. [RFC 7235 Appendix
///     B](https://datatracker.ietf.org/doc/html/rfc7235#appendix-B) references
///     the `quoted-string` rule from [RFC 7230 section
///     3.2.6](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6),
///     which allows these via `obs-text`, but the meaning is ill-defined in
///     the context of RFC 7235.
/// *   Reads a `token68` as [RFC 9110 section
///     11.6.1](https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1) allows
///     it: the first and only element after the scheme and one space, followed
///     by OWS, a comma or the end. `Negotiate` replies carry one ([RFC 4559
///     section 4](https://www.rfc-editor.org/rfc/rfc4559#section-4)), often in
///     the same field as other challenges. Where the grammar is ambiguous, as
///     `x=` could start a parameter, the parameter is taken when a value
///     follows.
pub struct ChallengeParser<'i> {
    input: &'i str,
    pos: usize,
    state: State<'i>,
}

impl<'i> ChallengeParser<'i> {
    pub fn new(input: &'i str) -> Self {
        ChallengeParser {
            input,
            pos: 0,
            state: State::PreToken {
                challenge: None,
                next: Possibilities(P_SCHEME),
            },
        }
    }
}

/// Describes a parse error and where in the input it occurs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error<'i> {
    input: &'i str,
    pos: usize,
    error: &'static str,
}

impl<'i> Error<'i> {
    fn invalid_byte(input: &'i str, pos: usize) -> Self {
        Self {
            input,
            pos,
            error: "invalid byte",
        }
    }
}

impl<'i> Display for Error<'i> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at byte {}: {:?}",
            self.error,
            self.pos,
            format_args!(
                "{}(HERE-->){}",
                &self.input[..self.pos],
                &self.input[self.pos..]
            ),
        )
    }
}

impl<'i> std::error::Error for Error<'i> {}

/// A set of zero or more `P_*` values indicating possibilities for the current
/// and/or upcoming tokens.
#[derive(Copy, Clone, PartialEq, Eq)]
struct Possibilities(u8);

const P_SCHEME: u8 = 1;
const P_PARAM_KEY: u8 = 2;
const P_EOF: u8 = 4;
const P_WHITESPACE: u8 = 8;
const P_COMMA_PARAM_KEY: u8 = 16; // a comma, then a param_key.
const P_COMMA_EOF: u8 = 32; // a comma, then eof.

impl std::fmt::Debug for Possibilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_set();
        if (self.0 & P_SCHEME) != 0 {
            l.entry(&"scheme");
        }
        if (self.0 & P_PARAM_KEY) != 0 {
            l.entry(&"param_key");
        }
        if (self.0 & P_EOF) != 0 {
            l.entry(&"eof");
        }
        if (self.0 & P_WHITESPACE) != 0 {
            l.entry(&"whitespace");
        }
        if (self.0 & P_COMMA_PARAM_KEY) != 0 {
            l.entry(&"comma_param_key");
        }
        if (self.0 & P_COMMA_EOF) != 0 {
            l.entry(&"comma_eof");
        }
        l.finish()
    }
}

enum State<'i> {
    Done,

    /// Consuming OWS and commas, then advancing to `Token`.
    PreToken {
        challenge: Option<ChallengeRef<'i>>,
        next: Possibilities,
    },

    /// Parsing a scheme/parameter key, or the whitespace immediately following it.
    Token {
        /// Current `challenge`, if any. If none, this token must be a scheme.
        challenge: Option<ChallengeRef<'i>>,
        token_pos: Range<usize>,
        cur: Possibilities, // subset of P_SCHEME|P_PARAM_KEY
    },

    /// Transitioned from `Token` or `PostToken` on first `=` after parameter key.
    /// Kept there for BWS in param case.
    PostEquals {
        challenge: ChallengeRef<'i>,
        key_pos: Range<usize>,
    },

    /// Transitioned from `Equals` on initial `C_TCHAR`.
    ParamUnquotedValue {
        challenge: ChallengeRef<'i>,
        key_pos: Range<usize>,
        value_start: usize,
    },

    /// A challenge's `token68`, from `start`; `equals` once its trailing `=`
    /// padding began.
    Token68 {
        challenge: ChallengeRef<'i>,
        start: usize,
        equals: bool,
    },

    /// Transitioned from `Equals` on initial `"`.
    ParamQuotedValue {
        challenge: ChallengeRef<'i>,
        key_pos: Range<usize>,
        value_start: usize,
        escapes: usize,
        in_backslash: bool,
    },
}

impl<'i> Iterator for ChallengeParser<'i> {
    type Item = Result<ChallengeRef<'i>, Error<'i>>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.input.len() {
            let b = self.input.as_bytes()[self.pos];
            let classes = char_classes(b);
            match std::mem::replace(&mut self.state, State::Done) {
                State::Done => return None,
                State::PreToken { challenge, next } => {
                    trace!(
                        "PreToken({:?}) pos={} b={:?}",
                        next,
                        self.pos,
                        char::from(b)
                    );
                    if (classes & C_OWS) != 0 && (next.0 & P_WHITESPACE) != 0 {
                        self.state = State::PreToken {
                            challenge,
                            next: Possibilities(next.0 & !P_EOF),
                        }
                    } else if b == b',' {
                        let next = Possibilities(
                            next.0
                                | P_WHITESPACE
                                | P_SCHEME
                                | if (next.0 & P_COMMA_PARAM_KEY) != 0 {
                                    P_PARAM_KEY
                                } else {
                                    0
                                }
                                | if (next.0 & P_COMMA_EOF) != 0 {
                                    P_EOF
                                } else {
                                    0
                                },
                        );
                        self.state = State::PreToken { challenge, next }
                    } else if (classes & C_TCHAR) != 0 {
                        self.state = State::Token {
                            challenge,
                            token_pos: self.pos..self.pos + 1,
                            cur: Possibilities(next.0 & (P_SCHEME | P_PARAM_KEY)),
                        }
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::Token {
                    challenge,
                    token_pos,
                    cur,
                } => {
                    trace!(
                        "Token({:?}, {:?}) pos={} b={:?}, cur challenge = {:#?}",
                        token_pos,
                        cur,
                        self.pos,
                        char::from(b),
                        challenge
                    );
                    if (classes & C_TCHAR) != 0 {
                        if token_pos.end == self.pos {
                            self.state = State::Token {
                                challenge,
                                token_pos: token_pos.start..self.pos + 1,
                                cur,
                            };
                        } else {
                            // Ending a scheme, starting a parameter key without an intermediate comma.
                            // The whitespace between must be exactly one space.
                            if (cur.0 & P_SCHEME) == 0
                                || &self.input[token_pos.end..self.pos] != " "
                            {
                                return Some(Err(Error::invalid_byte(self.input, self.pos)));
                            }
                            self.state = State::Token {
                                challenge: Some(ChallengeRef::new(&self.input[token_pos])),
                                token_pos: self.pos..self.pos + 1,
                                cur: Possibilities(P_PARAM_KEY),
                            };
                            if let Some(c) = challenge {
                                self.pos += 1;
                                return Some(Ok(c));
                            }
                        }
                    } else {
                        let first = first_element(challenge.as_ref(), cur);
                        match b {
                            // The first element after a scheme continues as a
                            // token68 at a character only token68 allows.
                            b'/' if first
                                && token_pos.end == self.pos
                                && is_token68(&self.input[token_pos.clone()]) =>
                            {
                                self.state = State::Token68 {
                                    challenge: challenge.expect("first element has a challenge"),
                                    start: token_pos.start,
                                    equals: false,
                                };
                            }
                            // A scheme, one space, then a token68 starting with one.
                            b'/' if (cur.0 & P_SCHEME) != 0
                                && token_pos.end != self.pos
                                && &self.input[token_pos.end..self.pos] == " " =>
                            {
                                self.state = State::Token68 {
                                    challenge: ChallengeRef::new(&self.input[token_pos]),
                                    start: self.pos,
                                    equals: false,
                                };
                                if let Some(c) = challenge {
                                    self.pos += 1;
                                    return Some(Ok(c));
                                }
                            }
                            // A first element without `=` before the comma is a token68.
                            b',' if first && is_token68(&self.input[token_pos.clone()]) => {
                                let mut challenge =
                                    challenge.expect("first element has a challenge");
                                challenge.token68 = Some(&self.input[token_pos]);
                                self.state = State::PreToken {
                                    challenge: Some(challenge),
                                    next: Possibilities(
                                        P_SCHEME | P_WHITESPACE | P_EOF | P_COMMA_EOF,
                                    ),
                                };
                            }
                            b',' if (cur.0 & P_SCHEME) != 0 => {
                                self.state = State::PreToken {
                                    challenge: Some(ChallengeRef::new(&self.input[token_pos])),
                                    next: Possibilities(
                                        P_SCHEME | P_WHITESPACE | P_EOF | P_COMMA_EOF,
                                    ),
                                };
                                if let Some(c) = challenge {
                                    self.pos += 1;
                                    return Some(Ok(c));
                                }
                            }
                            b'=' if (cur.0 & P_PARAM_KEY) != 0 => match challenge {
                                Some(challenge) => {
                                    self.state = State::PostEquals {
                                        challenge,
                                        key_pos: token_pos,
                                    }
                                }
                                None => {
                                    return Some(Err(Error {
                                        input: self.input,
                                        pos: self.pos,
                                        error: "= without existing challenge",
                                    }));
                                }
                            },

                            b' ' | b'\t' => {
                                self.state = State::Token {
                                    challenge,
                                    token_pos,
                                    cur,
                                }
                            }

                            _ => return Some(Err(Error::invalid_byte(self.input, self.pos))),
                        }
                    }
                }
                State::PostEquals {
                    mut challenge,
                    key_pos,
                } => {
                    trace!("PostEquals pos={} b={:?}", self.pos, char::from(b));
                    let token68 = token68_padding(self.input, &challenge, &key_pos);
                    if b == b'=' && token68 && self.pos == key_pos.end + 1 {
                        self.state = State::Token68 {
                            challenge,
                            start: key_pos.start,
                            equals: true,
                        };
                    } else if b == b',' && token68 {
                        challenge.token68 = Some(&self.input[key_pos.start..key_pos.end + 1]);
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(P_SCHEME | P_WHITESPACE | P_EOF | P_COMMA_EOF),
                        };
                    } else if (classes & C_OWS) != 0 {
                        // Note this doesn't advance key_pos.end, so in the token68 case, another
                        // `=` will not be allowed.
                        self.state = State::PostEquals { challenge, key_pos };
                    } else if b == b'"' {
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start: self.pos + 1,
                            escapes: 0,
                            in_backslash: false,
                        };
                    } else if (classes & C_TCHAR) != 0 {
                        self.state = State::ParamUnquotedValue {
                            challenge,
                            key_pos,
                            value_start: self.pos,
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::Token68 {
                    mut challenge,
                    start,
                    equals,
                } => {
                    trace!("Token68 pos={} b={:?}", self.pos, char::from(b));
                    if b == b'=' || (!equals && is_token68(&self.input[self.pos..self.pos + 1])) {
                        self.state = State::Token68 {
                            challenge,
                            start,
                            equals: equals || b == b'=',
                        };
                    } else if (classes & C_OWS) != 0 || b == b',' {
                        challenge.token68 = Some(&self.input[start..self.pos]);
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(if b == b',' {
                                P_SCHEME | P_WHITESPACE | P_EOF | P_COMMA_EOF
                            } else {
                                P_WHITESPACE | P_COMMA_EOF
                            }),
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::ParamUnquotedValue {
                    mut challenge,
                    key_pos,
                    value_start,
                } => {
                    trace!("ParamUnquotedValue pos={} b={:?}", self.pos, char::from(b));
                    if (classes & C_TCHAR) != 0 {
                        self.state = State::ParamUnquotedValue {
                            challenge,
                            key_pos,
                            value_start,
                        };
                    } else if (classes & C_OWS) != 0 {
                        challenge.params.push((
                            &self.input[key_pos],
                            ParamValue {
                                escapes: 0,
                                escaped: &self.input[value_start..self.pos],
                            },
                        ));
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(P_WHITESPACE | P_COMMA_PARAM_KEY | P_COMMA_EOF),
                        };
                    } else if b == b',' {
                        challenge.params.push((
                            &self.input[key_pos],
                            ParamValue {
                                escapes: 0,
                                escaped: &self.input[value_start..self.pos],
                            },
                        ));
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(
                                P_WHITESPACE
                                    | P_PARAM_KEY
                                    | P_SCHEME
                                    | P_EOF
                                    | P_COMMA_PARAM_KEY
                                    | P_COMMA_EOF,
                            ),
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
                State::ParamQuotedValue {
                    mut challenge,
                    key_pos,
                    value_start,
                    escapes,
                    in_backslash,
                } => {
                    trace!("ParamQuotedValue pos={} b={:?}", self.pos, char::from(b));
                    if in_backslash {
                        if (classes & C_ESCAPABLE) == 0 {
                            return Some(Err(Error::invalid_byte(self.input, self.pos)));
                        }
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start,
                            escapes: escapes + 1,
                            in_backslash: false,
                        };
                    } else if b == b'\\' {
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start,
                            escapes,
                            in_backslash: true,
                        };
                    } else if b == b'"' {
                        challenge.params.push((
                            &self.input[key_pos],
                            ParamValue {
                                escapes,
                                escaped: &self.input[value_start..self.pos],
                            },
                        ));
                        self.state = State::PreToken {
                            challenge: Some(challenge),
                            next: Possibilities(
                                P_WHITESPACE | P_EOF | P_COMMA_PARAM_KEY | P_COMMA_EOF,
                            ),
                        };
                    } else if (classes & C_QDTEXT) != 0 {
                        self.state = State::ParamQuotedValue {
                            challenge,
                            key_pos,
                            value_start,
                            escapes,
                            in_backslash,
                        };
                    } else {
                        return Some(Err(Error::invalid_byte(self.input, self.pos)));
                    }
                }
            };
            self.pos += 1;
        }
        match std::mem::replace(&mut self.state, State::Done) {
            State::Done => {}
            State::PreToken {
                challenge, next, ..
            } => {
                trace!("eof, PreToken({:?})", next);
                if (next.0 & P_EOF) == 0 {
                    return Some(Err(Error {
                        input: self.input,
                        pos: self.input.len(),
                        error: "unexpected EOF",
                    }));
                }
                if let Some(challenge) = challenge {
                    return Some(Ok(challenge));
                }
            }
            State::Token {
                challenge,
                token_pos,
                cur,
            } => {
                trace!("eof, Token({:?})", cur);
                if first_element(challenge.as_ref(), cur)
                    && token_pos.end == self.input.len()
                    && is_token68(&self.input[token_pos.clone()])
                {
                    let mut challenge = challenge.expect("first element has a challenge");
                    challenge.token68 = Some(&self.input[token_pos]);
                    return Some(Ok(challenge));
                }
                if (cur.0 & P_SCHEME) == 0 {
                    return Some(Err(Error {
                        input: self.input,
                        pos: self.input.len(),
                        error: "unexpected EOF expecting =",
                    }));
                }
                if token_pos.end != self.input.len() && &self.input[token_pos.end..] != " " {
                    return Some(Err(Error {
                        input: self.input,
                        pos: self.input.len(),
                        error: "EOF after whitespace",
                    }));
                }
                if let Some(challenge) = challenge {
                    self.state = State::Token {
                        challenge: None,
                        token_pos,
                        cur,
                    };
                    return Some(Ok(challenge));
                }
                return Some(Ok(ChallengeRef::new(&self.input[token_pos])));
            }
            State::PostEquals {
                mut challenge,
                key_pos,
            } if token68_padding(self.input, &challenge, &key_pos)
                && key_pos.end + 1 == self.input.len() =>
            {
                trace!("eof, PostEquals as token68");
                challenge.token68 = Some(&self.input[key_pos.start..key_pos.end + 1]);
                return Some(Ok(challenge));
            }
            State::Token68 {
                mut challenge,
                start,
                ..
            } => {
                trace!("eof, Token68");
                challenge.token68 = Some(&self.input[start..]);
                return Some(Ok(challenge));
            }
            State::PostEquals { .. } => {
                trace!("eof, PostEquals");
                return Some(Err(Error {
                    input: self.input,
                    pos: self.input.len(),
                    error: "unexpected EOF expecting param value",
                }));
            }
            State::ParamUnquotedValue {
                mut challenge,
                key_pos,
                value_start,
            } => {
                trace!("eof, ParamUnquotedValue");
                challenge.params.push((
                    &self.input[key_pos],
                    ParamValue {
                        escapes: 0,
                        escaped: &self.input[value_start..],
                    },
                ));
                return Some(Ok(challenge));
            }
            State::ParamQuotedValue { .. } => {
                trace!("eof, ParamQuotedValue");
                return Some(Err(Error {
                    input: self.input,
                    pos: self.input.len(),
                    error: "unexpected EOF in quoted param value",
                }));
            }
        }
        None
    }
}

impl std::iter::FusedIterator for ChallengeParser<'_> {}

/// Whether a token in the current state is the first element after its
/// challenge's scheme, the only place a token68 may stand.
fn first_element(challenge: Option<&ChallengeRef<'_>>, cur: Possibilities) -> bool {
    cur.0 == P_PARAM_KEY && challenge.is_some_and(|c| c.params.is_empty() && c.token68.is_none())
}

/// Whether `value` is made only of token68's non-padding characters.
fn is_token68(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/'))
}

/// Whether a first key and the `=` right after it are a token68 and its
/// padding rather than a parameter waiting for its value.
fn token68_padding(input: &str, challenge: &ChallengeRef<'_>, key: &Range<usize>) -> bool {
    challenge.params.is_empty()
        && challenge.token68.is_none()
        && input.as_bytes().get(key.end) == Some(&b'=')
        && is_token68(&input[key.clone()])
}

#[cfg(test)]
mod tests {
    use crate::{ChallengeRef, ParamValue};

    // A couple basic tests. The fuzz testing is far more comprehensive.

    #[test]
    fn multi_challenge() {
        // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
        let input =
            r#"Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple""#;
        let challenges = crate::parse_challenges(input).unwrap();
        assert_eq!(
            &challenges[..],
            &[
                ChallengeRef {
                    scheme: "Newauth",
                    params: vec![
                        ("realm", ParamValue::new(0, "apps")),
                        ("type", ParamValue::new(0, "1")),
                        ("title", ParamValue::new(2, r#"Login to \"apps\""#)),
                    ],
                    token68: None,
                },
                ChallengeRef {
                    scheme: "Basic",
                    params: vec![("realm", ParamValue::new(0, "simple")),],
                    token68: None,
                },
            ]
        );
    }

    fn shape(input: &str) -> Vec<(&str, Option<&str>, Vec<&str>)> {
        crate::parse_challenges(input)
            .unwrap_or_else(|e| panic!("{input:?}: {e}"))
            .into_iter()
            .map(|c| (c.scheme, c.token68, c.params.iter().map(|(k, _)| *k).collect()))
            .collect()
    }

    #[test]
    fn token68_stands_alone_after_its_scheme() {
        for (input, expected) in [
            ("Negotiate abc", vec![("Negotiate", Some("abc"), vec![])]),
            ("Negotiate abc=", vec![("Negotiate", Some("abc="), vec![])]),
            ("Negotiate YII/+a.b_c~d-e==", vec![("Negotiate", Some("YII/+a.b_c~d-e=="), vec![])]),
            ("Negotiate /abc", vec![("Negotiate", Some("/abc"), vec![])]),
            (
                r#"Negotiate AQ==, Basic realm="x""#,
                vec![("Negotiate", Some("AQ=="), vec![]), ("Basic", None, vec!["realm"])],
            ),
            (
                r#"Basic realm="x", Negotiate AQ=="#,
                vec![("Basic", None, vec!["realm"]), ("Negotiate", Some("AQ=="), vec![])],
            ),
            (
                r#"Negotiate abc= , Digest realm="a, b", nonce="n""#,
                vec![("Negotiate", Some("abc="), vec![]), ("Digest", None, vec!["realm", "nonce"])],
            ),
            ("Negotiate abc, Negotiate", vec![("Negotiate", Some("abc"), vec![]), ("Negotiate", None, vec![])]),
            ("Negotiate, NTLM", vec![("Negotiate", None, vec![]), ("NTLM", None, vec![])]),
            // A value after `=` makes a parameter, even after bad whitespace.
            ("Scheme a=b", vec![("Scheme", None, vec!["a"])]),
            ("Scheme a= b", vec![("Scheme", None, vec!["a"])]),
            ("Scheme a=b, c=d", vec![("Scheme", None, vec!["a", "c"])]),
        ] {
            assert_eq!(shape(input), expected, "{input:?}");
        }
    }

    #[test]
    fn token68_is_refused_where_the_grammar_has_no_room_for_it() {
        for input in [
            "Negotiate abc=d/e",
            "Negotiate abc==x",
            "Negotiate abc def",
            "Negotiate abc, def=x",
            "Negotiate a!b",
            "Negotiate a!b/",
            "Negotiate abc= =",
            "Scheme a=b, c/",
            "Negotiate  abc",
            "Negotiate =",
            // Trailing whitespace ends a header value no more than after a parameter.
            "Negotiate abc ",
            "Negotiate abc= ",
            "Negotiate abc== ",
        ] {
            assert!(crate::parse_challenges(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn empty() {
        crate::parse_challenges("").unwrap_err();
        crate::parse_challenges(",").unwrap_err();
    }
}
