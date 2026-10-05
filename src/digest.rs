// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Digest` authentication scheme, as in
//! [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616).

use std::{convert::TryFrom, fmt::Write as _, io::Write as _};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use digest::Digest;

use crate::{
    char_classes, ChallengeRef, ParamValue, PasswordParams, C_ATTR, C_ESCAPABLE, C_QDTEXT,
};

/// "Quality of protection" value.
///
/// The values here can be used in a bitmask as in [`DigestClient::qop`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Qop {
    /// Authentication.
    Auth = 1,

    /// Authentication with integrity protection.
    ///
    /// "Integrity protection" means protection of the request entity body.
    AuthInt = 2,
}

impl Qop {
    /// Returns a string form as expected over the wire.
    fn as_str(self) -> &'static str {
        match self {
            Qop::Auth => "auth",
            Qop::AuthInt => "auth-int",
        }
    }
}

/// A set of zero or more [`Qop`]s.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct QopSet(u8);

impl std::fmt::Debug for QopSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_set();
        if (self.0 & Qop::Auth as u8) != 0 {
            l.entry(&"auth");
        }
        if (self.0 & Qop::AuthInt as u8) != 0 {
            l.entry(&"auth-int");
        }
        l.finish()
    }
}

impl std::ops::BitAnd<Qop> for QopSet {
    type Output = bool;

    fn bitand(self, rhs: Qop) -> Self::Output {
        (self.0 & (rhs as u8)) != 0
    }
}

/// Client for a `Digest` challenge, as in [RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616).
///
/// This can be constructed by the `TryFrom<&ChallengeRef<'_>>` impl. However,
/// in most cases this client should be used only indirectly through the more
/// abstract [`crate::PasswordClient`].
///
/// Most of the information here is taken from the `WWW-Authenticate` or
/// `Proxy-Authenticate` header. This also internally maintains a nonce counter.
///
/// ## Implementation notes
///
/// *   Recalculates `H(A1)` on each [`DigestClient::respond`] call. It'd be
///     more CPU-efficient to calculate `H(A1)` only once by supplying the
///     username and password at construction time or by caching (username,
///     password) -> `H(A1)` mappings internally. `DigestClient` prioritizes
///     simplicity instead.
/// *   There's no support yet for parsing the `Authentication-Info` and
///     `Proxy-Authentication-Info` header fields described by [RFC 7616 section
///     3.5](https://datatracker.ietf.org/doc/html/rfc7616#section-3.5).
///     PRs welcome!
/// *   Uses ASCII credentials unless the challenge explicitly declares UTF-8.
/// *   Supports [RFC 2069](https://datatracker.ietf.org/doc/html/rfc2069) compatibility as in
///     [RFC 2617 section 3.2.2.1](https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.2.1),
///     even though RFC 7616 drops it. There are still RTSP cameras being sold
///     in 2021 that use the RFC 2069-style calculations.
/// *   Supports RFC 7616 `userhash`, even though it seems impractical and only
///     marginally useful. The server must index the userhash for each supported
///     algorithm or calculate it on-the-fly for all users in the database.
/// *   The `-sess` algorithm variants haven't been tested; there's no example
///     in the RFCs.
///
/// ## Security considerations
///
/// We strongly advise *servers* against implementing `Digest`:
///
/// *   It's actively harmful in that it prevents the server from securing their
///     password storage via salted password hashes. See [RFC 7616 Section
///     5.2](https://datatracker.ietf.org/doc/html/rfc7616#section-5.2).
///     When your server offers `Digest` authentication, it is advertising that
///     it stores plaintext passwords!
/// *   It's no replacement for TLS in terms of protecting confidentiality of
///     the password, much less confidentiality of any other information.
///
/// For *clients*, when a server supports both `Digest` and `Basic`, we advise
/// using `Digest`. It provides (slightly) more confidentiality of passwords
/// over the wire.
///
/// Some servers *only* support `Digest`. E.g.,
/// [ONVIF](https://www.onvif.org/profiles/specifications/) mandates the
/// `Digest` scheme. It doesn't prohibit implementing other schemes, but some
/// cameras meet the specification's requirement and do no more.
#[derive(Eq, PartialEq)]
pub struct DigestClient {
    /// Holds unescaped versions of all string fields.
    ///
    /// Using a single `String` minimizes the size of the `DigestClient`
    /// itself and/or any option/enum it may be wrapped in. It also minimizes
    /// padding bytes after each allocation. The fields as stored as follows:
    ///
    /// 1.  `realm`: `[0, domain_start)`
    /// 2.  `domain`: `[domain_start, opaque_start)`
    /// 3.  `opaque`: `[opaque_start, nonce_start)`
    /// 4.  `nonce`: `[nonce_start, buf.len())`
    buf: Box<str>,

    // Positions described in `buf` comment above. See respective methods' doc
    // comments for more information. These are stored as `u16` to save space,
    // and because it's unreasonable for them to be large.
    domain_start: u16,
    opaque_start: u16,
    nonce_start: u16,

    // Non-string fields. See respective methods' doc comments for more information.
    algorithm: Algorithm,
    session: bool,
    stale: bool,
    rfc2069_compat: bool,
    userhash: bool,
    utf8: bool,
    qop: QopSet,
    nc: u32,
}

impl DigestClient {
    /// Replace the server nonce only after the caller has authenticated the
    /// Authentication-Info that supplied it. The same nonce retains its count.
    pub fn adopt_verified_nonce(&mut self, nonce: &str) -> Result<(), String> {
        if nonce.is_empty()
            || !is_valid_quoted_value(nonce)
            || usize::from(self.nonce_start) + nonce.len() > usize::from(u16::MAX)
        {
            return Err("invalid next nonce".into());
        }
        if nonce == self.nonce() {
            return Ok(());
        }
        let mut value = String::with_capacity(usize::from(self.nonce_start) + nonce.len());
        value.push_str(&self.buf[..usize::from(self.nonce_start)]);
        value.push_str(nonce);
        self.buf = value.into_boxed_str();
        self.nc = 0;
        Ok(())
    }
    /// Returns a string to be displayed to users so they know which username
    /// and password to use.
    ///
    /// This string should contain at least the name of
    /// the host performing the authentication and might additionally
    /// indicate the collection of users who might have access.  An
    /// example is `registered_users@example.com`.  (See [Section 2.2 of
    /// RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235#section-2.2) for
    /// more details.)
    #[inline]
    pub fn realm(&self) -> &str {
        &self.buf[..self.domain_start as usize]
    }

    /// Returns the domain, a space-separated list of URIs, as specified in RFC
    /// 3986, that define the protection space.
    ///
    /// If the domain parameter is absent, returns an empty string, which is semantically
    /// identical according to the RFC.
    #[inline]
    pub fn domain(&self) -> &str {
        &self.buf[self.domain_start as usize..self.opaque_start as usize]
    }

    /// Returns the nonce, a server-specified string which should be uniquely
    /// generated each time a 401 response is made.
    #[inline]
    pub fn nonce(&self) -> &str {
        &self.buf[self.nonce_start as usize..]
    }

    /// Returns string of data, specified by the server, that SHOULD be returned
    /// by the client unchanged in the Authorization header field of subsequent
    /// requests with URIs in the same protection space.
    ///
    /// Currently an empty `opaque` is treated as an absent one.
    #[inline]
    pub fn opaque(&self) -> Option<&str> {
        if self.opaque_start == self.nonce_start {
            None
        } else {
            Some(&self.buf[self.opaque_start as usize..self.nonce_start as usize])
        }
    }

    /// Returns a flag indicating that the previous request from the client was
    /// rejected because the nonce value was stale.
    #[inline]
    pub fn stale(&self) -> bool {
        self.stale
    }

    /// Returns true if using [RFC 2069](https://datatracker.ietf.org/doc/html/rfc2069)
    /// compatibility mode as in [RFC 2617 section
    /// 3.2.2.1](https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.2.1).
    ///
    /// If so, `request-digest` is calculated without the nonce count, conce, or qop.
    #[inline]
    pub fn rfc2069_compat(&self) -> bool {
        self.rfc2069_compat
    }

    /// Returns the algorithm used to produce the digest and an unkeyed digest.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns if the session style `A1` will be used.
    #[inline]
    pub fn session(&self) -> bool {
        self.session
    }

    /// Returns the `qop` (quality of protection) values the server offered:
    /// none for a challenge without `qop`, which is answered in the
    /// [`DigestClient::rfc2069_compat`] form.
    #[inline]
    pub fn qop(&self) -> QopSet {
        self.qop
    }

    /// Returns the number of times the server-supplied nonce has been used by
    /// [`DigestClient::respond`].
    #[inline]
    pub fn nonce_count(&self) -> u32 {
        self.nc
    }

    /// Responds to the challenge with the supplied parameters.
    ///
    /// The caller should use the returned string as an `Authorization` or
    /// `Proxy-Authorization` header value.
    #[inline]
    pub fn respond(&mut self, p: &PasswordParams) -> Result<String, String> {
        self.respond_protected(p)
            .map(|response| response.authorization.to_string())
    }

    /// Responds using a fixed cnonce **for testing only**.
    ///
    /// In production code, use [`DigestClient::respond`] instead, which generates a new
    /// random cnonce value.
    #[inline]
    pub fn respond_with_testing_cnonce(
        &mut self,
        p: &PasswordParams,
        cnonce: &str,
    ) -> Result<String, String> {
        self.respond_inner(p, cnonce)
            .map(|response| response.authorization.to_string())
    }

    /// Helper for respond methods.
    ///
    /// We don't simply implement this as `respond_with_testing_cnonce` and have
    /// `respond` delegate to that method because it'd be confusing/alarming if
    /// that method name ever shows up in production stack traces.
    /// Restrict response construction to the explicitly selected offered qop.
    pub fn select_qop(&mut self, selected: Option<Qop>) -> Result<(), String> {
        match selected {
            None if self.rfc2069_compat => Ok(()),
            Some(qop) if !self.rfc2069_compat && self.qop & qop => {
                self.qop = QopSet(qop as u8);
                Ok(())
            }
            _ => Err("selected qop was not offered".into()),
        }
    }
    /// Construct one response with an explicitly offered qop, preserving the
    /// server offer and the shared nonce count for subsequent requests.
    pub fn respond_with_qop_protected(
        &mut self,
        p: &PasswordParams,
        selected: Option<Qop>,
    ) -> Result<DigestResponse, String> {
        let offered = self.qop;
        self.select_qop(selected)?;
        let response = self.respond_protected(p);
        self.qop = offered;
        response
    }
    pub fn respond_protected(&mut self, p: &PasswordParams) -> Result<DigestResponse, String> {
        self.respond_inner(p, &new_random_cnonce())
    }
    fn respond_inner(
        &mut self,
        p: &PasswordParams,
        cnonce: &str,
    ) -> Result<DigestResponse, String> {
        if !self.utf8 && (!p.username.is_ascii() || !p.password.is_ascii()) {
            return Err("non-ASCII credentials require an explicit UTF-8 challenge".into());
        }
        let username = Zeroizing::new(if self.utf8 {
            p.username.nfc().collect::<String>()
        } else {
            p.username.to_owned()
        });
        let password = Zeroizing::new(if self.utf8 {
            p.password.nfc().collect::<String>()
        } else {
            p.password.to_owned()
        });
        let realm = self.realm();
        let mut h_a1 = Zeroizing::new(self.algorithm.h(&[
            username.as_bytes(),
            b":",
            realm.as_bytes(),
            b":",
            password.as_bytes(),
        ]));
        if self.session {
            h_a1 = Zeroizing::new(self.algorithm.h(&[
                h_a1.as_bytes(),
                b":",
                self.nonce().as_bytes(),
                b":",
                cnonce.as_bytes(),
            ]));
        }

        // Select the best available qop and calculate H(A2) as in
        // [https://datatracker.ietf.org/doc/html/rfc7616#section-3.4.3].
        let (h_a2, qop);
        if let (Some(body), true) = (p.body, self.qop & Qop::AuthInt) {
            let body_hash = Zeroizing::new(self.algorithm.h(&[body]));
            h_a2 = self.algorithm.h(&[
                p.method.as_bytes(),
                b":",
                p.uri.as_bytes(),
                b":",
                body_hash.as_bytes(),
            ]);
            qop = Qop::AuthInt;
        } else if self.rfc2069_compat || self.qop & Qop::Auth {
            h_a2 = self
                .algorithm
                .h(&[p.method.as_bytes(), b":", p.uri.as_bytes()]);
            qop = Qop::Auth;
        } else {
            return Err("no supported/available qop".into());
        }

        let nc = self.nc.checked_add(1).ok_or("nonce count exhausted")?;
        let mut hex_nc = [0u8; 8];
        let _ = write!(&mut hex_nc[..], "{:08x}", nc);
        let str_hex_nc = match std::str::from_utf8(&hex_nc[..]) {
            Ok(h) => h,
            Err(_) => unreachable!(),
        };

        // https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.2.1
        let response = Zeroizing::new(if self.rfc2069_compat {
            self.algorithm.h(&[
                h_a1.as_bytes(),
                b":",
                self.nonce().as_bytes(),
                b":",
                h_a2.as_bytes(),
            ])
        } else {
            self.algorithm.h(&[
                h_a1.as_bytes(),
                b":",
                self.nonce().as_bytes(),
                b":",
                &hex_nc[..],
                b":",
                cnonce.as_bytes(),
                b":",
                qop.as_str().as_bytes(),
                b":",
                h_a2.as_bytes(),
            ])
        });

        let mut out = Zeroizing::new(String::with_capacity(128));
        out.push_str("Digest ");
        if self.userhash {
            let hashed = self
                .algorithm
                .h(&[username.as_bytes(), b":", realm.as_bytes()]);
            append_quoted_key_value(&mut out, "username", &hashed)?;
            append_unquoted_key_value(&mut out, "userhash", "true");
        } else if is_valid_quoted_value(&username) {
            append_quoted_key_value(&mut out, "username", &username)?;
        } else {
            append_extended_key_value(&mut out, "username", &username);
        }
        append_quoted_key_value(&mut out, "realm", self.realm())?;
        append_quoted_key_value(&mut out, "uri", p.uri)?;
        append_quoted_key_value(&mut out, "nonce", self.nonce())?;
        if !self.rfc2069_compat {
            append_unquoted_key_value(&mut out, "algorithm", self.algorithm.as_str(self.session));
            append_unquoted_key_value(&mut out, "nc", str_hex_nc);
            append_quoted_key_value(&mut out, "cnonce", cnonce)?;
            append_unquoted_key_value(&mut out, "qop", qop.as_str());
        }
        append_quoted_key_value(&mut out, "response", &response)?;
        if let Some(o) = self.opaque() {
            append_quoted_key_value(&mut out, "opaque", o)?;
        }
        if self.rfc2069_compat && (self.session || self.algorithm != Algorithm::Md5) {
            append_unquoted_key_value(&mut out, "algorithm", self.algorithm.as_str(self.session));
        }
        if self.rfc2069_compat && self.session {
            append_quoted_key_value(&mut out, "cnonce", cnonce)?;
        }
        let length = out.len() - 2;
        out.truncate(length);
        self.nc = nc;
        Ok(DigestResponse {
            authorization: out,
            proof: ServerProof {
                algorithm: self.algorithm,
                h_a1,
                nonce: Zeroizing::new(self.nonce().to_owned()),
                cnonce: Zeroizing::new(cnonce.to_owned()),
                nc,
                uri: Zeroizing::new(p.uri.to_owned()),
                qop: if self.rfc2069_compat { None } else { Some(qop) },
            },
        })
    }
}

/// Why a [`DigestSession`] adopted no challenge from a 401 or 407.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Unanswerable {
    /// No challenge names the `Digest` scheme.
    NotOffered,
    /// Every Digest challenge offers only `auth-int`, which this session's
    /// holder cannot answer.
    OnlyAuthInt,
    /// No Digest challenge can be read, such as one naming only unknown
    /// algorithms.
    Invalid,
}

/// A Digest client across the requests it answers (RFC 7616 section 3.3), as
/// curl keeps one per connection and httpx one per auth flow: the challenge it
/// adopted, whose nonce each later request reuses with the next count, until
/// the server challenges again or proves a `nextnonce`.
///
/// A holder answers a 401 or 407 by passing its challenges to
/// [`DigestSession::challenged`] and sending the request again with
/// [`DigestSession::respond`]'s answer; later requests carry an answer from
/// the start. What the server replies goes to [`DigestSession::replied`].
pub struct DigestSession {
    client: Option<DigestClient>,
    auth_int: bool,
}

impl std::fmt::Debug for DigestSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestSession")
            .field("adopted", &self.client.is_some())
            .field("auth_int", &self.auth_int)
            .finish()
    }
}

impl DigestSession {
    /// A session without a challenge. `auth_int` says whether its holder can
    /// answer `auth-int`: it has each request's whole body when it answers,
    /// and each reply's whole body when it checks the server's proof, whose
    /// hash covers it.
    pub fn new(auth_int: bool) -> Self {
        Self {
            client: None,
            auth_int,
        }
    }

    /// Adopts the first Digest challenge among `values` (the
    /// `WWW-Authenticate` or `Proxy-Authenticate` field lines of a 401 or
    /// 407) this client can answer, as RFC 7616 section 3.7 has a client do:
    /// one it cannot read, such as one naming an unknown algorithm, is passed
    /// over, and so is one offering only `auth-int` when the holder cannot
    /// answer it. Any challenge adopted before is dropped, since the server
    /// refused it: its nonce went stale, or the credential was wrong.
    pub fn challenged<'a>(
        &mut self,
        values: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Unanswerable> {
        self.client = None;
        let (mut offered, mut only_auth_int) = (false, false);
        for value in values {
            let Ok(parsed) = crate::parse_challenges(value) else {
                continue;
            };
            for challenge in parsed {
                if !challenge.scheme.eq_ignore_ascii_case("Digest") {
                    continue;
                }
                offered = true;
                let Ok(client) = DigestClient::try_from(&challenge) else {
                    continue;
                };
                if client.rfc2069_compat()
                    || client.qop() & Qop::Auth
                    || (self.auth_int && client.qop() & Qop::AuthInt)
                {
                    self.client = Some(client);
                    return Ok(());
                }
                only_auth_int = true;
            }
        }
        Err(if only_auth_int {
            Unanswerable::OnlyAuthInt
        } else if offered {
            Unanswerable::Invalid
        } else {
            Unanswerable::NotOffered
        })
    }

    /// Answers one request with the adopted challenge and the next count of
    /// its nonce, or `None` before any challenge was adopted. `auth` is
    /// answered where offered, as curl and httpx prefer it; `auth-int` only
    /// where it is the one offered, which needs `p.body`.
    pub fn respond(&mut self, p: &PasswordParams) -> Result<Option<DigestResponse>, String> {
        let Some(client) = &mut self.client else {
            return Ok(None);
        };
        let qop = if client.rfc2069_compat() {
            None
        } else if client.qop() & Qop::Auth {
            Some(Qop::Auth)
        } else if p.body.is_some() {
            Some(Qop::AuthInt)
        } else {
            return Err("the challenge offers only auth-int, which needs the request body".into());
        };
        client.respond_with_qop_protected(p, qop).map(Some)
    }

    /// Takes the reply to a request answered with `proof`: every field line of
    /// its `Authentication-Info` (`Proxy-Authentication-Info` from a proxy)
    /// and its body. A proof it carries must verify; a `nextnonce` it proves
    /// is adopted for the requests that follow, and one it does not prove is
    /// not.
    pub fn replied<'a>(
        &mut self,
        proof: &ServerProof,
        lines: impl IntoIterator<Item = &'a [u8]>,
        body: &[u8],
    ) -> Result<ServerInfo, String> {
        let info = proof.verify(lines, body)?;
        if let (
            ServerInfo::Proven {
                next_nonce: Some(next),
            },
            Some(client),
        ) = (&info, &mut self.client)
        {
            client.adopt_verified_nonce(next)?;
        }
        Ok(info)
    }
}

impl TryFrom<&ChallengeRef<'_>> for DigestClient {
    type Error = String;

    fn try_from(value: &ChallengeRef<'_>) -> Result<Self, Self::Error> {
        if !value.scheme.eq_ignore_ascii_case("Digest") {
            return Err(format!(
                "DigestClientContext doesn't support challenge scheme {:?}",
                value.scheme
            ));
        }
        if value.token68.is_some() {
            return Err("digest challenge carries a token68".into());
        }
        let mut buf_len = 0;
        let mut unused_len = 0;
        let mut realm = None;
        let mut domain = None;
        let mut nonce = None;
        let mut opaque = None;
        let mut stale = false;
        let mut algorithm_and_session = None;
        let mut qop_str = None;
        let mut userhash_str = None;
        let mut selectors = std::collections::HashSet::new();
        let mut utf8 = false;

        // Parse response header field parameters as in
        // [https://datatracker.ietf.org/doc/html/rfc7616#section-3.3].
        for (k, v) in &value.params {
            if !selectors.insert(k.to_ascii_lowercase()) {
                return Err("duplicate digest parameter".into());
            }
            if k.eq_ignore_ascii_case("charset") {
                utf8 = true;
            }
            if k.eq_ignore_ascii_case("charset") && !v.escaped.eq_ignore_ascii_case("UTF-8") {
                return Err("unsupported digest charset".into());
            }
            if (k.eq_ignore_ascii_case("stale") || k.eq_ignore_ascii_case("userhash"))
                && !v.escaped.eq_ignore_ascii_case("true")
                && !v.escaped.eq_ignore_ascii_case("false")
            {
                return Err("invalid digest boolean".into());
            }
            // Note that "stale" and "algorithm" can be directly compared
            // without unescaping because RFC 7616 section 3.3 says "For
            // historical reasons, a sender MUST NOT generate the quoted string
            // syntax values for the following parameters: stale and algorithm."
            if store_param(k, v, "realm", &mut realm, &mut buf_len)?
                || store_param(k, v, "domain", &mut domain, &mut buf_len)?
                || store_param(k, v, "nonce", &mut nonce, &mut buf_len)?
                || store_param(k, v, "opaque", &mut opaque, &mut buf_len)?
                || store_param(k, v, "qop", &mut qop_str, &mut unused_len)?
                || store_param(k, v, "userhash", &mut userhash_str, &mut unused_len)?
            {
                // Do nothing here.
            } else if k.eq_ignore_ascii_case("stale") {
                stale = v.escaped.eq_ignore_ascii_case("true");
            } else if k.eq_ignore_ascii_case("algorithm") {
                algorithm_and_session = Some(Algorithm::parse(v.escaped)?);
            }
        }
        let realm = realm.ok_or("missing required parameter realm")?;
        let nonce = nonce.ok_or("missing required parameter nonce")?;
        if buf_len > u16::MAX as usize {
            // Incredibly unlikely, but just for completeness.
            return Err(format!(
                "Unescaped parameters' length {} exceeds u16::MAX!",
                buf_len
            ));
        }

        let algorithm_and_session = algorithm_and_session.unwrap_or((Algorithm::Md5, false));

        let mut buf = String::with_capacity(buf_len);
        let mut qop = QopSet(0);
        let rfc2069_compat = if let Some(qop_str) = qop_str {
            let qop_str = qop_str.unescaped_with_scratch(&mut buf);
            for v in qop_str.split(',') {
                let v = v.trim();
                if v.eq_ignore_ascii_case("auth") {
                    qop.0 |= Qop::Auth as u8;
                } else if v.eq_ignore_ascii_case("auth-int") {
                    qop.0 |= Qop::AuthInt as u8;
                }
            }
            if qop.0 == 0 {
                return Err(format!("no supported qop in {:?}", qop_str));
            }
            buf.clear();
            false
        } else {
            // No qop is offered: the response takes the RFC 2069 form, whose
            // A2 is that of "auth" (RFC 7616 section 3.4.3).
            true
        };
        let userhash;
        if let Some(userhash_str) = userhash_str {
            let userhash_str = userhash_str.unescaped_with_scratch(&mut buf);
            userhash = userhash_str.eq_ignore_ascii_case("true");
            buf.clear();
        } else {
            userhash = false;
        };
        realm.append_unescaped(&mut buf);
        let domain_start = buf.len();
        if let Some(d) = domain {
            d.append_unescaped(&mut buf);
        }
        let opaque_start = buf.len();
        if let Some(o) = opaque {
            o.append_unescaped(&mut buf);
        }
        let nonce_start = buf.len();
        nonce.append_unescaped(&mut buf);
        Ok(DigestClient {
            buf: buf.into_boxed_str(),
            domain_start: domain_start as u16,
            opaque_start: opaque_start as u16,
            nonce_start: nonce_start as u16,
            algorithm: algorithm_and_session.0,
            session: algorithm_and_session.1,
            stale,
            rfc2069_compat,
            userhash,
            utf8,
            qop,
            nc: 0,
        })
    }
}

impl std::fmt::Debug for DigestClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DigestClient")
            .field("realm", &self.realm())
            .field("domain", &self.domain())
            .field("opaque", &self.opaque())
            .field("nonce", &self.nonce())
            .field("algorithm", &self.algorithm.as_str(self.session))
            .field("stale", &self.stale)
            .field("qop", &self.qop)
            .field("rfc2069_compat", &self.rfc2069_compat)
            .field("userhash", &self.userhash)
            .field("nc", &self.nc)
            .finish()
    }
}

/// Helper for `DigestClient::try_from` which stashes away a `&ParamValue`.
#[inline(never)]
fn store_param<'v, 'tmp>(
    k: &'tmp str,
    v: &'v ParamValue<'v>,
    expected_k: &'tmp str,
    set_v: &'tmp mut Option<&'v ParamValue<'v>>,
    add_len: &'tmp mut usize,
) -> Result<bool, String> {
    if !k.eq_ignore_ascii_case(expected_k) {
        return Ok(false);
    }
    if set_v.is_some() {
        return Err(format!("duplicate parameter {:?}", k));
    }
    *add_len += v.unescaped_len();
    *set_v = Some(v);
    Ok(true)
}

fn is_valid_quoted_value(s: &str) -> bool {
    for &b in s.as_bytes() {
        if char_classes(b) & (C_QDTEXT | C_ESCAPABLE) == 0 {
            return false;
        }
    }
    true
}

fn append_extended_key_value(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str("*=UTF-8''");
    for &b in value.as_bytes() {
        if (char_classes(b) & C_ATTR) != 0 {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{:02X}", b);
        }
    }
    out.push_str(", ");
}

#[inline(never)]
fn append_unquoted_key_value(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push('=');
    out.push_str(value);
    out.push_str(", ");
}

#[inline(never)]
fn append_quoted_key_value(out: &mut String, key: &str, value: &str) -> Result<(), String> {
    out.push_str(key);
    out.push_str("=\"");
    let mut first_unwritten = 0;
    let bytes = value.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        // Note that bytes >= 128 are in neither C_QDTEXT nor C_ESCAPABLE, so every allowed byte
        // is a full UTF-8 code point.
        let class = char_classes(b);
        if (class & C_QDTEXT) != 0 {
            // Just advance.
        } else if (class & C_ESCAPABLE) != 0 {
            out.push_str(&value[first_unwritten..i]);
            out.push('\\');
            out.push(char::from(b));
            first_unwritten = i + 1;
        } else {
            return Err(format!("invalid {} value {:?}", key, value));
        }
    }
    out.push_str(&value[first_unwritten..]);
    out.push_str("\", ");
    Ok(())
}

/// Supported algorithm from the [HTTP Digest Algorithm Values
/// registry](https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml).
///
/// This doesn't store whether the session variant (`<Algorithm>-sess`) was
/// requested; see [`DigestClient::session`] for that.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Algorithm {
    Md5,
    Sha256,
    Sha512Trunc256,
}

impl Algorithm {
    /// Parses a string into a tuple of `Algorithm` and a bool representing
    /// whether the `-sess` suffix is present.
    fn parse(s: &str) -> Result<(Self, bool), String> {
        Ok(match s {
            "MD5" => (Algorithm::Md5, false),
            "MD5-sess" => (Algorithm::Md5, true),
            "SHA-256" => (Algorithm::Sha256, false),
            "SHA-256-sess" => (Algorithm::Sha256, true),
            "SHA-512-256" => (Algorithm::Sha512Trunc256, false),
            "SHA-512-256-sess" => (Algorithm::Sha512Trunc256, true),
            _ => return Err(format!("unknown algorithm {:?}", s)),
        })
    }

    #[inline(never)]
    fn as_str(&self, session: bool) -> &'static str {
        match (self, session) {
            (Algorithm::Md5, false) => "MD5",
            (Algorithm::Md5, true) => "MD5-sess",
            (Algorithm::Sha256, false) => "SHA-256",
            (Algorithm::Sha256, true) => "SHA-256-sess",
            (Algorithm::Sha512Trunc256, false) => "SHA-512-256",
            (Algorithm::Sha512Trunc256, true) => "SHA-512-256-sess",
        }
    }

    #[inline(never)]
    fn h(&self, items: &[&[u8]]) -> String {
        match self {
            Algorithm::Md5 => h(md5::Md5::new(), items),
            Algorithm::Sha256 => h(sha2::Sha256::new(), items),
            Algorithm::Sha512Trunc256 => h(sha2::Sha512_256::new(), items),
        }
    }
}

fn h<D: Digest>(mut d: D, items: &[&[u8]]) -> String {
    for i in items {
        d.update(i);
    }
    hex::encode(d.finalize())
}

fn new_random_cnonce() -> String {
    let raw: [u8; 16] = rand::random();
    hex::encode(&raw[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Tests the example from [RFC 7616 section 3.9.1: SHA-256 and
    /// MD5](https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.1).
    #[test]
    fn sha256_and_md5() {
        let www_authenticate = "\
            Digest \
            realm=\"http-auth@example.org\", \
            qop=\"auth, auth-int\", \
            algorithm=SHA-256, \
            nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
            opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", \
            Digest \
            realm=\"http-auth@example.org\", \
            qop=\"auth, auth-int\", \
            algorithm=MD5, \
            nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
            opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
        let challenges = dbg!(crate::parse_challenges(www_authenticate).unwrap());
        assert_eq!(challenges.len(), 2);
        let ctxs: Result<Vec<_>, _> = challenges.iter().map(DigestClient::try_from).collect();
        let mut ctxs = dbg!(ctxs.unwrap());
        assert_eq!(ctxs[1].realm(), "http-auth@example.org");
        assert_eq!(ctxs[1].domain(), "");
        assert_eq!(
            ctxs[1].nonce(),
            "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"
        );
        assert_eq!(
            ctxs[1].opaque(),
            Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")
        );
        assert_eq!(ctxs[1].stale(), false);
        assert_eq!(ctxs[1].algorithm(), Algorithm::Md5);
        assert_eq!(ctxs[1].qop().0, (Qop::Auth as u8) | (Qop::AuthInt as u8));
        assert_eq!(ctxs[1].nonce_count(), 0);
        let params = crate::PasswordParams {
            username: "Mufasa",
            password: "Circle of Life",
            uri: "/dir/index.html",
            body: None,
            method: "GET",
        };
        assert_eq!(
            &mut ctxs[0]
                .respond_with_testing_cnonce(
                    &params,
                    "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
                )
                .unwrap(),
            "Digest username=\"Mufasa\", \
                    realm=\"http-auth@example.org\", \
                    uri=\"/dir/index.html\", \
                    nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                    algorithm=SHA-256, \
                    nc=00000001, \
                    cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", \
                    qop=auth, \
                    response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\", \
                    opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        );
        assert_eq!(ctxs[0].nc, 1);
        assert_eq!(
            &mut ctxs[1]
                .respond_with_testing_cnonce(
                    &params,
                    "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
                )
                .unwrap(),
            "Digest username=\"Mufasa\", \
                    realm=\"http-auth@example.org\", \
                    uri=\"/dir/index.html\", \
                    nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                    algorithm=MD5, \
                    nc=00000001, \
                    cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", \
                    qop=auth, \
                    response=\"8ca523f5e9506fed4657c9700eebdbec\", \
                    opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        );
        assert_eq!(ctxs[1].nc, 1);
    }

    /// Tests a made-up example with `MD5-sess`. There's no example in the RFC,
    /// and these values haven't been tested against any other implementation.
    /// But having the test here ensures we don't accidentally change the
    /// algorithm.
    #[test]
    fn md5_sess() {
        let www_authenticate = "\
            Digest \
            realm=\"http-auth@example.org\", \
            qop=\"auth, auth-int\", \
            algorithm=MD5-sess, \
            nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
            opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
        let challenges = dbg!(crate::parse_challenges(www_authenticate).unwrap());
        assert_eq!(challenges.len(), 1);
        let ctxs: Result<Vec<_>, _> = challenges.iter().map(DigestClient::try_from).collect();
        let mut ctxs = dbg!(ctxs.unwrap());
        assert_eq!(ctxs[0].realm(), "http-auth@example.org");
        assert_eq!(ctxs[0].domain(), "");
        assert_eq!(
            ctxs[0].nonce(),
            "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"
        );
        assert_eq!(
            ctxs[0].opaque(),
            Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")
        );
        assert_eq!(ctxs[0].stale(), false);
        assert_eq!(ctxs[0].algorithm(), Algorithm::Md5);
        assert_eq!(ctxs[0].session(), true);
        assert_eq!(ctxs[0].qop().0, (Qop::Auth as u8) | (Qop::AuthInt as u8));
        assert_eq!(ctxs[0].nonce_count(), 0);
        let params = crate::PasswordParams {
            username: "Mufasa",
            password: "Circle of Life",
            uri: "/dir/index.html",
            body: None,
            method: "GET",
        };
        assert_eq!(
            &mut ctxs[0]
                .respond_with_testing_cnonce(
                    &params,
                    "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
                )
                .unwrap(),
            "Digest username=\"Mufasa\", \
                    realm=\"http-auth@example.org\", \
                    uri=\"/dir/index.html\", \
                    nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
                    algorithm=MD5-sess, \
                    nc=00000001, \
                    cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", \
                    qop=auth, \
                    response=\"e783283f46242139c486a698fec7211d\", \
                    opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        );
        assert_eq!(ctxs[0].nc, 1);
    }

    /// Tests the example from [RFC 7616 section 3.9.2: SHA-512-256, Charset, and
    /// Userhash](https://datatracker.ietf.org/doc/html/rfc7616#section-3.9.2).
    #[test]
    fn sha512_256_charset() {
        let www_authenticate = "\
            Digest \
            realm=\"api@example.org\", \
            qop=\"auth\", \
            algorithm=SHA-512-256, \
            nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
            opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", \
            charset=UTF-8, \
            userhash=true";
        let challenges = dbg!(crate::parse_challenges(www_authenticate).unwrap());
        assert_eq!(challenges.len(), 1);
        let ctxs: Result<Vec<_>, _> = challenges.iter().map(DigestClient::try_from).collect();
        let mut ctxs = dbg!(ctxs.unwrap());
        assert_eq!(ctxs.len(), 1);
        assert_eq!(ctxs[0].realm(), "api@example.org");
        assert_eq!(ctxs[0].domain(), "");
        assert_eq!(
            ctxs[0].nonce(),
            "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK"
        );
        assert_eq!(
            ctxs[0].opaque(),
            Some("HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS")
        );
        assert_eq!(ctxs[0].stale, false);
        assert_eq!(ctxs[0].userhash, true);
        assert_eq!(ctxs[0].algorithm, Algorithm::Sha512Trunc256);
        assert_eq!(ctxs[0].qop.0, Qop::Auth as u8);
        assert_eq!(ctxs[0].nc, 0);
        let params = crate::PasswordParams {
            username: "J\u{E4}s\u{F8}n Doe",
            password: "Secret, or not?",
            uri: "/doe.json",
            body: None,
            method: "GET",
        };

        // Note the username and response values in the RFC are *wrong*!
        // https://www.rfc-editor.org/errata/eid4897
        assert_eq!(
            &mut ctxs[0]
                .respond_with_testing_cnonce(
                    &params,
                    "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v"
                )
                .unwrap(),
            "\
            Digest \
            username=\"793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b\", \
            userhash=true, \
            realm=\"api@example.org\", \
            uri=\"/doe.json\", \
            nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
            algorithm=SHA-512-256, \
            nc=00000001, \
            cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", \
            qop=auth, \
            response=\"3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5\", \
            opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\""
        );
        assert_eq!(ctxs[0].nc, 1);
        ctxs[0].userhash = false;
        ctxs[0].nc = 0;
        assert_eq!(
            &mut ctxs[0]
                .respond_with_testing_cnonce(
                    &params,
                    "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v"
                )
                .unwrap(),
            "\
            Digest \
            username*=UTF-8''J%C3%A4s%C3%B8n%20Doe, \
            realm=\"api@example.org\", \
            uri=\"/doe.json\", \
            nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", \
            algorithm=SHA-512-256, \
            nc=00000001, \
            cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", \
            qop=auth, \
            response=\"3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5\", \
            opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\""
        );
        assert_eq!(ctxs[0].nc, 1);
    }

    #[test]
    fn rfc2069() {
        // https://datatracker.ietf.org/doc/html/rfc2069#section-2.4
        // The response there is wrong! See https://www.rfc-editor.org/errata/eid749
        let www_authenticate = "\
            Digest \
            realm=\"testrealm@host.com\", \
            nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
            opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        let challenges = dbg!(crate::parse_challenges(www_authenticate).unwrap());
        assert_eq!(challenges.len(), 1);
        let ctxs: Result<Vec<_>, _> = challenges.iter().map(DigestClient::try_from).collect();
        let mut ctxs = dbg!(ctxs.unwrap());
        assert_eq!(ctxs.len(), 1);
        assert_eq!(ctxs[0].qop.0, 0);
        assert_eq!(ctxs[0].rfc2069_compat, true);
        let params = crate::PasswordParams {
            username: "Mufasa",
            password: "CircleOfLife",
            uri: "/dir/index.html",
            body: None,
            method: "GET",
        };
        assert_eq!(
            &mut ctxs[0]
                .respond_with_testing_cnonce(&params, "unused")
                .unwrap(),
            "\
            Digest \
            username=\"Mufasa\", \
            realm=\"testrealm@host.com\", \
            uri=\"/dir/index.html\", \
            nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
            response=\"1949323746fe6a43ef61f9606e7febea\", \
            opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        );
        assert_eq!(ctxs[0].nc, 1);
    }

    // See sizes with: cargo test -- --nocapture digest::tests::size
    #[test]
    fn size() {
        // This type should have a niche.
        assert_eq!(
            dbg!(std::mem::size_of::<DigestClient>()),
            dbg!(std::mem::size_of::<Option<DigestClient>>()),
        )
    }
}

/// One protected request and its response-verification context. Neither Debug
/// nor serialization exposes the authorization, password hash or nonce proof.
pub struct DigestResponse {
    pub authorization: Zeroizing<String>,
    pub proof: ServerProof,
}
pub struct ServerProof {
    algorithm: Algorithm,
    h_a1: Zeroizing<String>,
    nonce: Zeroizing<String>,
    cnonce: Zeroizing<String>,
    nc: u32,
    uri: Zeroizing<String>,
    qop: Option<Qop>,
}
/// What a response's `Authentication-Info` (`Proxy-Authentication-Info` from a
/// proxy) says of the request a [`ServerProof`] answers.
#[derive(Debug, PartialEq, Eq)]
pub enum ServerInfo {
    /// The server computed `rspauth`, which only a holder of the password can;
    /// its `nextnonce`, if any, may be adopted.
    Proven { next_nonce: Option<String> },
    /// The server sent no field, or, without qop, a field without `rspauth`
    /// (RFC 7616 section 3.5 requires one only with qop). Nothing is proven,
    /// and a `nextnonce` in it is not to be adopted.
    Unproven,
}
impl ServerProof {
    /// Verify the field lines of a response's `Authentication-Info` against
    /// this exact request and the received body. The lines are one list (RFC
    /// 9110 section 5.3); a parameter in two of them is refused. A `nextnonce`
    /// is returned as private protocol state and never applied here.
    pub fn verify<'a>(
        &self,
        lines: impl IntoIterator<Item = &'a [u8]>,
        body: &[u8],
    ) -> Result<ServerInfo, String> {
        use subtle::ConstantTimeEq;
        let mut joined = Zeroizing::new(String::new());
        let mut present = false;
        for line in lines {
            present = true;
            let line = std::str::from_utf8(line).map_err(|_| "authentication-info is not text")?;
            let line = line.trim_matches([' ', '\t', ',']);
            if !line.is_empty() {
                if !joined.is_empty() {
                    joined.push_str(", ");
                }
                joined.push_str(line);
            }
        }
        if !present {
            return Ok(ServerInfo::Unproven);
        }
        let input = Zeroizing::new(format!("Digest {}", joined.as_str()));
        let parsed = crate::parse_challenges(&input).map_err(|_| "invalid authentication-info")?;
        if parsed.len() != 1 {
            return Err("ambiguous authentication-info".into());
        }
        let mut fields = std::collections::HashMap::new();
        for (key, value) in &parsed[0].params {
            if fields
                .insert(
                    key.to_ascii_lowercase(),
                    Zeroizing::new(value.to_unescaped()),
                )
                .is_some()
            {
                return Err("duplicate authentication-info parameter".into());
            }
        }
        let get = |name: &str| {
            fields
                .get(name)
                .map(|v| v.as_str())
                .ok_or("missing authentication-info parameter")
        };
        if let Some(qop) = self.qop {
            if get("qop")? != qop.as_str()
                || get("nc")? != format!("{:08x}", self.nc)
                || get("cnonce")? != self.cnonce.as_str()
            {
                return Err("authentication-info does not match the request".into());
            }
        } else if fields.contains_key("qop")
            || fields.contains_key("nc")
            || fields.contains_key("cnonce")
        {
            return Err("unexpected authentication-info qop".into());
        } else if !fields.contains_key("rspauth") {
            return Ok(ServerInfo::Unproven);
        }
        let a2 = Zeroizing::new(match self.qop {
            Some(Qop::AuthInt) => {
                let body_hash = Zeroizing::new(self.algorithm.h(&[body]));
                self.algorithm
                    .h(&[b":", self.uri.as_bytes(), b":", body_hash.as_bytes()])
            }
            _ => self.algorithm.h(&[b":", self.uri.as_bytes()]),
        });
        let expected = Zeroizing::new(match self.qop {
            Some(qop) => self.algorithm.h(&[
                self.h_a1.as_bytes(),
                b":",
                self.nonce.as_bytes(),
                b":",
                format!("{:08x}", self.nc).as_bytes(),
                b":",
                self.cnonce.as_bytes(),
                b":",
                qop.as_str().as_bytes(),
                b":",
                a2.as_bytes(),
            ]),
            None => self.algorithm.h(&[
                self.h_a1.as_bytes(),
                b":",
                self.nonce.as_bytes(),
                b":",
                a2.as_bytes(),
            ]),
        });
        let received = Zeroizing::new(hex::decode(get("rspauth")?).map_err(|_| "invalid rspauth")?);
        let expected =
            Zeroizing::new(hex::decode(expected.as_str()).map_err(|_| "invalid expected rspauth")?);
        if received.len() != expected.len() || !bool::from(received.ct_eq(&expected)) {
            return Err("rspauth mismatch".into());
        }
        Ok(ServerInfo::Proven {
            next_nonce: fields.get("nextnonce").map(|value| value.to_string()),
        })
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    // Independently generated with Python hashlib for all RFC 7616 hashes,
    // session variants, and qop modes; request/response bodies are binary.
    #[test]
    fn binary_integrity_session_variants_and_server_proofs() {
        let vectors = [
            (
                "MD5",
                None,
                "e199d75235f96fde73108ca54db65ec6",
                "813d5f74cbc2d11ff7903a6add0b318e",
            ),
            (
                "MD5",
                Some(Qop::Auth),
                "b8b01581d5a531ccde1afd3afc6c63f9",
                "c519f1e321f470bf48167692dfbe9a96",
            ),
            (
                "MD5",
                Some(Qop::AuthInt),
                "a28f59162314fb9344cc50ba2d30b6d3",
                "089d9a9f8ad52444a737200a79276439",
            ),
            (
                "MD5-sess",
                None,
                "434a160394171017b12ad07cb1ae63a3",
                "5ec0953fe78ff2c6f0e6b254b7fc443d",
            ),
            (
                "MD5-sess",
                Some(Qop::Auth),
                "0e652557b0d2a1575a71e71f93c59b66",
                "5678ec9fe21f20f1daf326f8d5424627",
            ),
            (
                "MD5-sess",
                Some(Qop::AuthInt),
                "d4daa8d0c83d65e4a7b6bb64c03ccf9f",
                "269359c69134a49bdf1311fd7b61f573",
            ),
            (
                "SHA-256",
                None,
                "4e9a4d81293c43b8edb3f6f7113db636134a871ef6ba7876e503a6d9275c6d69",
                "8aac29544060ff89452e0fb51b02705901fb8ff048df84817a885c00e7027552",
            ),
            (
                "SHA-256",
                Some(Qop::Auth),
                "c5c9ad7df4be39a2eee1a6e64addecdef95d210c4dc14dd933ffea2fc33cd7ef",
                "767f87ac829f806a4cbbc246c44ec5d9937939607e84cb8e63f2b7813ea91f01",
            ),
            (
                "SHA-256",
                Some(Qop::AuthInt),
                "c6678f7f9551f2093a9bbfbd9dbd6d0d6479d14f40c9640a76202c8c796a774e",
                "54f9bc5d52edfab3f4e4d5f689f6baf9c79f59d5c70a0f4b2533c69663ffa703",
            ),
            (
                "SHA-256-sess",
                None,
                "5feed50c3134bf37a035b4efc2965d987311866f863ab22fb4105426aa68c8b0",
                "d47e48816967c8ee98211f8b0ef8ff4c843744e4af016516779f4073723ccb49",
            ),
            (
                "SHA-256-sess",
                Some(Qop::Auth),
                "5e19814d2c0d67d9860496cb7ff6d47be4c7cbed72cad9c99d0bd63ab8d39808",
                "dc82d43716a79382f06079945d9f984b3ad2e66bcdf9256c17bcb82324541245",
            ),
            (
                "SHA-256-sess",
                Some(Qop::AuthInt),
                "8acecb0f8579220c820455b5e0a1d101ad42a90c7299faba7097afdfd8b8bf7b",
                "a4cf3b5311aa069a5d0aab1600458d8b5d8c18de287fd3816d33050a18b04c5b",
            ),
            (
                "SHA-512-256",
                None,
                "94ef20a12aab79231b1b197c3341e251c37e617f596b4c4b4450b6408fd70c47",
                "d3c2d57deea1a117db900d9913a9994da1b4e89ef87bad5e853b4179c3abaa22",
            ),
            (
                "SHA-512-256",
                Some(Qop::Auth),
                "cd30d4c398e6da752b02ca3a9eb3e5c959c9a38ba025e596a780e154502e8d1b",
                "54662ed6a3425c2e641b19a6f5dd00bbece5f4c373a9ba7dbec26614567e0d1c",
            ),
            (
                "SHA-512-256",
                Some(Qop::AuthInt),
                "ace6e59c939fa65dd2767a8c8f7eac5cf5a47bc0853c671c236bd610af947c11",
                "1f2406f3f5598a8e0c6793544d12c338ffb26d6cfad7c0968feeba0e8b8bca9b",
            ),
            (
                "SHA-512-256-sess",
                None,
                "76cf0f9cddb4d2fcca62e8018ff8dd4dc6324a51876862360eefa3c3abc62c11",
                "4b7563abb21f001f31b46a9ea969e196bbc93fb825453b5e8f05b1bbdf939534",
            ),
            (
                "SHA-512-256-sess",
                Some(Qop::Auth),
                "4872eaec52281923295e4c7f603a70ef918e465e99275f75072f8ea04d04fc04",
                "8f1ee98f79ea8831203a0e4c8b9b45a9fec56fa5c9d7136c48a318bee7656d48",
            ),
            (
                "SHA-512-256-sess",
                Some(Qop::AuthInt),
                "107ced56c55edc5cc8940e7ab0cd8601415ca3e177400914b395df9d04ed04e4",
                "ccbbdec532b6545d152e04ea563e5692785f9800459446807de419bf702376f0",
            ),
        ];
        for (algorithm, qop, request_hash, response_hash) in vectors {
            let mut challenge = format!(
                "Digest realm=\"camera\", nonce=\"nonce-1\", algorithm={}",
                algorithm
            );
            if let Some(qop) = qop {
                challenge.push_str(&format!(", qop=\"{}\"", qop.as_str()));
            }
            let parsed = crate::parse_challenges(&challenge).unwrap();
            let mut client = DigestClient::try_from(&parsed[0]).unwrap();
            client.select_qop(qop).unwrap();
            let params = PasswordParams {
                username: "user",
                password: "p:ass",
                method: "SET_PARAMETER",
                uri: "rtsp://camera.invalid/media",
                body: Some(&[0, 255, 1, 13, 10]),
            };
            let response = client.respond_inner(&params, "c0ffee").unwrap();
            let parsed = crate::parse_challenges(&response.authorization).unwrap();
            assert_eq!(
                parsed[0]
                    .params
                    .iter()
                    .find(|(key, _)| *key == "response")
                    .unwrap()
                    .1
                    .to_unescaped(),
                request_hash,
                "{} {:?}",
                algorithm,
                qop
            );
            if algorithm.ends_with("-sess") {
                assert!(response.authorization.contains("cnonce=\"c0ffee\""));
                assert!(response
                    .authorization
                    .contains(&format!("algorithm={}", algorithm)));
            }
            let mut info = format!("rspauth=\"{}\", nextnonce=\"next-2\"", response_hash);
            if let Some(qop) = qop {
                info.push_str(&format!(
                    ", qop={}, nc=00000001, cnonce=\"c0ffee\"",
                    qop.as_str()
                ));
            }
            let proven = ServerInfo::Proven {
                next_nonce: Some("next-2".into()),
            };
            assert_eq!(
                response.proof.verify([info.as_bytes()], &[9, 0, 128]),
                Ok(proven)
            );
            if qop == Some(Qop::AuthInt) {
                assert!(response
                    .proof
                    .verify([info.as_bytes()], &[9, 0, 129])
                    .is_err());
            }
            assert!(response
                .proof
                .verify([info.replace(response_hash, "00").as_bytes()], &[9, 0, 128])
                .is_err());
            assert_eq!(client.nonce_count(), 1);
            assert_eq!(client.nonce(), "nonce-1");
            client.adopt_verified_nonce("nonce-1").unwrap();
            assert_eq!(client.nonce_count(), 1);
            client.adopt_verified_nonce("next-2").unwrap();
            assert_eq!(client.nonce_count(), 0);
            assert_eq!(client.realm(), "camera");
            client.nc = u32::MAX;
            assert!(client.respond_protected(&params).is_err());
            assert_eq!(client.nc, u32::MAX);
        }
    }
    /// The proof of the MD5 vector above, with or without qop=auth.
    fn md5_proof(qop: Option<Qop>) -> ServerProof {
        let mut challenge = "Digest realm=\"camera\", nonce=\"nonce-1\", algorithm=MD5".to_owned();
        if qop.is_some() {
            challenge.push_str(", qop=\"auth\"");
        }
        let parsed = crate::parse_challenges(&challenge).unwrap();
        let mut client = DigestClient::try_from(&parsed[0]).unwrap();
        client.select_qop(qop).unwrap();
        let params = PasswordParams {
            username: "user",
            password: "p:ass",
            method: "SET_PARAMETER",
            uri: "rtsp://camera.invalid/media",
            body: Some(&[0, 255, 1, 13, 10]),
        };
        client.respond_inner(&params, "c0ffee").unwrap().proof
    }
    #[test]
    fn authentication_info_lines_are_one_list() {
        let proof = md5_proof(Some(Qop::Auth));
        let rspauth = "rspauth=\"c519f1e321f470bf48167692dfbe9a96\"";
        let proven = |next: Option<&str>| {
            Ok(ServerInfo::Proven {
                next_nonce: next.map(str::to_owned),
            })
        };
        let lines: [&[u8]; 2] = [
            rspauth.as_bytes(),
            b"qop=auth, nc=00000001, cnonce=\"c0ffee\"",
        ];
        assert_eq!(proof.verify(lines, &[]), proven(None));
        // Empty lines and empty list elements are no parameters.
        let lines: [&[u8]; 4] = [
            b"",
            b", qop=auth,",
            rspauth.as_bytes(),
            b" nc=00000001, , cnonce=\"c0ffee\", nextnonce=\"n2\"",
        ];
        assert_eq!(proof.verify(lines, &[]), proven(Some("n2")));
        // A parameter in two lines, a line that is not text, a missing rspauth.
        let full = format!("{rspauth}, qop=auth, nc=00000001, cnonce=\"c0ffee\"");
        assert!(proof
            .verify([full.as_bytes(), rspauth.as_bytes()], &[])
            .is_err());
        assert!(proof.verify([full.as_bytes(), b"x=\"\xff\""], &[]).is_err());
        let lines: [&[u8]; 1] = [b"qop=auth, nc=00000001, cnonce=\"c0ffee\", nextnonce=\"n\""];
        assert!(proof.verify(lines, &[]).is_err());
        // No field at all proves nothing.
        assert_eq!(
            proof.verify(std::iter::empty(), &[]),
            Ok(ServerInfo::Unproven)
        );
    }
    #[test]
    fn without_qop_a_nextnonce_alone_proves_nothing() {
        let proof = md5_proof(None);
        let lines: [&[u8]; 1] = [b"nextnonce=\"n2\""];
        assert_eq!(proof.verify(lines, &[]), Ok(ServerInfo::Unproven));
        let lines: [&[u8]; 2] = [
            b"nextnonce=\"n2\"",
            b"rspauth=\"813d5f74cbc2d11ff7903a6add0b318e\"",
        ];
        assert_eq!(
            proof.verify(lines, &[9, 0, 128]),
            Ok(ServerInfo::Proven {
                next_nonce: Some("n2".into())
            })
        );
        let lines: [&[u8]; 1] = [b"rspauth=\"00\""];
        assert!(proof.verify(lines, &[]).is_err());
        let lines: [&[u8]; 1] = [b"nextnonce=\"n2\", nc=00000001"];
        assert!(proof.verify(lines, &[]).is_err());
    }
    #[test]
    fn per_request_qop_preserves_offer_on_success_and_failure() {
        let parsed =
            crate::parse_challenges("Digest realm=\"camera\",nonce=\"n\",qop=\"auth,auth-int\"")
                .unwrap();
        let mut client = DigestClient::try_from(&parsed[0]).unwrap();
        let mut p = PasswordParams {
            username: "user",
            password: "secret",
            method: "PLAY",
            uri: "rtsp://camera/a",
            body: None,
        };
        assert!(client
            .respond_with_qop_protected(&p, Some(Qop::AuthInt))
            .is_err());
        assert_eq!(client.nonce_count(), 0);
        let first = client
            .respond_with_qop_protected(&p, Some(Qop::Auth))
            .unwrap();
        assert!(first.authorization.contains("qop=auth,"));
        p.body = Some(&[0, 255]);
        let second = client
            .respond_with_qop_protected(&p, Some(Qop::AuthInt))
            .unwrap();
        assert!(second.authorization.contains("qop=auth-int,"));
        assert_eq!(client.nonce_count(), 2);
        assert!(client.qop() & Qop::Auth);
        assert!(client.qop() & Qop::AuthInt);
    }
    #[test]
    fn a_challenge_without_qop_offers_none_and_is_answered_without_one() {
        let parsed = crate::parse_challenges("Digest realm=\"r\", nonce=\"n\"").unwrap();
        let mut client = DigestClient::try_from(&parsed[0]).unwrap();
        assert!(client.rfc2069_compat());
        assert!(!(client.qop() & Qop::Auth));
        assert!(!(client.qop() & Qop::AuthInt));
        assert!(client.select_qop(Some(Qop::Auth)).is_err());
        client.select_qop(None).unwrap();
        let response = client
            .respond_protected(&PasswordParams {
                username: "Mufasa",
                password: "CircleOfLife",
                uri: "/dir/index.html",
                method: "GET",
                body: None,
            })
            .unwrap();
        assert!(!response.authorization.contains("qop="));
        assert!(!response.authorization.contains("cnonce="));
    }
    #[test]
    fn explicit_qop_and_duplicate_challenges_do_not_silently_fall_back() {
        let parsed =
            crate::parse_challenges("Digest realm=\"camera\",nonce=\"n\",qop=\"auth,auth-int\"")
                .unwrap();
        let mut client = DigestClient::try_from(&parsed[0]).unwrap();
        assert!(client.select_qop(None).is_err());
        client.select_qop(Some(Qop::AuthInt)).unwrap();
        assert!(client.select_qop(Some(Qop::Auth)).is_err());
        let p = PasswordParams {
            username: "user",
            password: "secret",
            method: "GET",
            uri: "/",
            body: None,
        };
        assert!(client.respond_protected(&p).is_err());
        assert_eq!(client.nc, 0);
        for suffix in [
            ", algorithm=MD5, Algorithm=SHA-256",
            ", stale=true, STALE=false",
            ", charset=unsupported",
            ", userhash=maybe",
        ] {
            let header = format!("Digest realm=\"camera\",nonce=\"n\"{}", suffix);
            let parsed = crate::parse_challenges(&header).unwrap();
            assert!(DigestClient::try_from(&parsed[0]).is_err());
        }
    }

    fn session_params(body: Option<&[u8]>) -> PasswordParams<'_> {
        PasswordParams {
            username: "user",
            password: "secret",
            method: "DESCRIBE",
            uri: "rtsp://camera.invalid/media",
            body,
        }
    }
    fn param<'a>(header: &'a str, key: &str) -> &'a str {
        let rest = &header[header.find(&format!(" {}=", key)).unwrap() + key.len() + 2..];
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        &rest[..rest.find(['"', ',']).unwrap_or(rest.len())]
    }
    #[test]
    fn a_session_adopts_the_first_challenge_it_can_answer() {
        let mut session = DigestSession::new(false);
        assert_eq!(
            session.challenged(["Basic realm=\"r\""]),
            Err(Unanswerable::NotOffered)
        );
        assert_eq!(
            session.challenged(["Digest realm=\"r\", nonce=\"n\", algorithm=SHA-999"]),
            Err(Unanswerable::Invalid)
        );
        let only_auth_int = "Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"";
        assert_eq!(
            session.challenged([only_auth_int]),
            Err(Unanswerable::OnlyAuthInt)
        );
        assert!(session.respond(&session_params(None)).unwrap().is_none());
        // Passed over for a later one, in another field line or the same.
        session
            .challenged([
                only_auth_int,
                "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-999, Digest realm=\"r\", nonce=\"later\", algorithm=SHA-256, qop=\"auth-int,auth\"",
            ])
            .unwrap();
        let answer = session
            .respond(&session_params(Some(b"body")))
            .unwrap()
            .unwrap();
        assert_eq!(param(&answer.authorization, "nonce"), "later");
        assert_eq!(param(&answer.authorization, "algorithm"), "SHA-256");
        // auth is preferred even with the body held.
        assert_eq!(param(&answer.authorization, "qop"), "auth");
        // A holder of whole bodies answers auth-int where it is all offered.
        let mut session = DigestSession::new(true);
        session.challenged([only_auth_int]).unwrap();
        assert!(session.respond(&session_params(None)).is_err());
        let answer = session
            .respond(&session_params(Some(b"body")))
            .unwrap()
            .unwrap();
        assert_eq!(param(&answer.authorization, "qop"), "auth-int");
    }
    #[test]
    fn a_session_counts_its_nonce_and_adopts_only_a_proven_next_one() {
        let mut session = DigestSession::new(false);
        session
            .challenged(["Digest realm=\"r\", nonce=\"n1\", qop=\"auth\""])
            .unwrap();
        let first = session.respond(&session_params(None)).unwrap().unwrap();
        let second = session.respond(&session_params(None)).unwrap().unwrap();
        for (answer, nc) in [(&first, "00000001"), (&second, "00000002")] {
            assert_eq!(param(&answer.authorization, "nonce"), "n1");
            assert_eq!(param(&answer.authorization, "nc"), nc);
        }
        let md5 = Algorithm::Md5;
        let cnonce = param(&second.authorization, "cnonce");
        let rspauth = md5.h(&[
            md5.h(&[b"user:r:secret"]).as_bytes(),
            b":n1:00000002:",
            cnonce.as_bytes(),
            b":auth:",
            md5.h(&[b":rtsp://camera.invalid/media"]).as_bytes(),
        ]);
        let info = format!(
            "rspauth=\"{}\", qop=auth, nc=00000002, cnonce=\"{}\", nextnonce=\"n2\"",
            rspauth, cnonce
        );
        assert_eq!(
            session.replied(&second.proof, [info.as_bytes()], &[]),
            Ok(ServerInfo::Proven {
                next_nonce: Some("n2".into())
            })
        );
        let third = session.respond(&session_params(None)).unwrap().unwrap();
        assert_eq!(param(&third.authorization, "nonce"), "n2");
        assert_eq!(param(&third.authorization, "nc"), "00000001");
        // A forged proof fails and adopts nothing.
        let forged = info.replace(&rspauth, &"0".repeat(32));
        assert!(session
            .replied(&second.proof, [forged.as_bytes()], &[])
            .is_err());
        // Without qop, a nextnonce alone proves nothing and is not adopted.
        let mut session = DigestSession::new(false);
        session
            .challenged(["Digest realm=\"r\", nonce=\"n1\""])
            .unwrap();
        let answer = session.respond(&session_params(None)).unwrap().unwrap();
        let lines: [&[u8]; 1] = [b"nextnonce=\"n2\""];
        assert_eq!(
            session.replied(&answer.proof, lines, &[]),
            Ok(ServerInfo::Unproven)
        );
        let next = session.respond(&session_params(None)).unwrap().unwrap();
        assert_eq!(param(&next.authorization, "nonce"), "n1");
        // A new challenge replaces the adopted one, and its count starts anew.
        session
            .challenged(["Digest realm=\"r\", nonce=\"n3\", stale=true, qop=\"auth\""])
            .unwrap();
        let fresh = session.respond(&session_params(None)).unwrap().unwrap();
        assert_eq!(param(&fresh.authorization, "nonce"), "n3");
        assert_eq!(param(&fresh.authorization, "nc"), "00000001");
    }
}
