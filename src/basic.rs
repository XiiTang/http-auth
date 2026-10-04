// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Basic` authentication scheme as in
//! [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).

use std::convert::TryFrom;
use zeroize::Zeroizing;

use crate::ChallengeRef;

/// Encodes the given credentials.
///
/// This can be used to preemptively send `Basic` authentication, without
/// sending an unauthenticated request and waiting for a `401 Unauthorized`
/// response.
///
/// The caller should use the returned string as an `Authorization` or
/// `Proxy-Authorization` header value.
///
/// The caller is responsible for `username` and `password` being in the
/// correct format. Servers may expect arguments to be in Unicode
/// Normalization Form C as noted in [RFC 7617 section
/// 2.1](https://datatracker.ietf.org/doc/html/rfc7617#section-2.1).
///
/// ```rust
/// assert_eq!(
///     http_auth::basic::encode_credentials("Aladdin", "open sesame"),
///     "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
/// );
pub fn encode_credentials(username: &str, password: &str) -> String {
    encode_protected(username, password).to_string()
}
/// Encode without leaving a plaintext temporary or an unprotected header owner.
pub fn encode_protected(username: &str, password: &str) -> Zeroizing<String> {
    use base64::Engine as _;
    let user_pass = Zeroizing::new(format!("{}:{}", username, password));
    const PREFIX: &str = "Basic ";
    let mut value = Zeroizing::new(String::with_capacity(
        PREFIX.len() + base64_encoded_len(user_pass.len()),
    ));
    value.push_str(PREFIX);
    base64::engine::general_purpose::STANDARD.encode_string(&user_pass[..], &mut value);
    value
}

/// Returns the base64-encoded length for the given input length, including padding.
fn base64_encoded_len(input_len: usize) -> usize {
    (input_len + 2) / 3 * 4
}

/// Client for a `Basic` challenge, as in
/// [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617).
///
/// The protected entry point requires ASCII or explicitly declared UTF-8,
/// and normalizes UTF-8 credentials to NFC before encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicClient {
    realm: Box<str>,
    utf8: bool,
}

impl BasicClient {
    pub fn respond_protected(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Zeroizing<String>, String> {
        use unicode_normalization::UnicodeNormalization;
        if username.contains(':')
            || username
                .bytes()
                .chain(password.bytes())
                .any(|b| b < 32 || b == 127)
        {
            return Err("invalid Basic credential characters".into());
        }
        if !self.utf8 && (!username.is_ascii() || !password.is_ascii()) {
            return Err("non-ASCII credentials require an explicit UTF-8 challenge".into());
        }
        let username = Zeroizing::new(username.nfc().collect::<String>());
        let password = Zeroizing::new(password.nfc().collect::<String>());
        Ok(encode_protected(&username, &password))
    }
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Responds to the challenge with the supplied parameters.
    ///
    /// This is functionally identical to [`encode_credentials`]; no parameters
    /// of the `BasicClient` are needed to produce the credentials.
    #[inline]
    pub fn respond(&self, username: &str, password: &str) -> String {
        encode_credentials(username, password)
    }
}

impl TryFrom<&ChallengeRef<'_>> for BasicClient {
    type Error = String;

    fn try_from(value: &ChallengeRef<'_>) -> Result<Self, Self::Error> {
        if !value.scheme.eq_ignore_ascii_case("Basic") {
            return Err(format!(
                "BasicClient doesn't support challenge scheme {:?}",
                value.scheme
            ));
        }
        if value.token68.is_some() {
            return Err("basic challenge carries a token68".into());
        }
        let mut realm = None;
        let mut utf8 = false;
        let mut seen = std::collections::HashSet::new();
        for (k, v) in &value.params {
            if !seen.insert(k.to_ascii_lowercase()) {
                return Err("duplicate basic parameter".into());
            }
            if k.eq_ignore_ascii_case("charset") {
                utf8 = true;
            }
            if k.eq_ignore_ascii_case("charset") && !v.escaped.eq_ignore_ascii_case("UTF-8") {
                return Err("unsupported basic charset".into());
            }
            if k.eq_ignore_ascii_case("realm") {
                realm = Some(v.to_unescaped());
            }
        }
        let realm = realm.ok_or("missing required parameter realm")?;
        Ok(BasicClient {
            realm: realm.into_boxed_str(),
            utf8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        // Example from https://datatracker.ietf.org/doc/html/rfc7617#section-2
        let ctx = BasicClient {
            realm: "WallyWorld".into(),
            utf8: false,
        };
        assert_eq!(
            ctx.respond("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );

        // Example from https://datatracker.ietf.org/doc/html/rfc7617#section-2.1
        // Note that this crate *always* uses UTF-8, not just when the server requests it.
        let ctx = BasicClient {
            realm: "foo".into(),
            utf8: true,
        };
        assert_eq!(ctx.respond("test", "123\u{A3}"), "Basic dGVzdDoxMjPCow==");
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    #[test]
    fn protected_basic_requires_unambiguous_characters_and_declared_utf8() {
        let parsed = crate::parse_challenges("Basic realm=\"camera\", charset=\"UTF-8\"").unwrap();
        let client = BasicClient::try_from(&parsed[0]).unwrap();
        assert_eq!(
            client
                .respond_protected("te\u{301}st", "pa\u{308}ss")
                .unwrap()
                .as_str(),
            "Basic dMOpc3Q6cMOkc3M="
        );
        assert!(client.respond_protected("user:name", "password").is_err());
        assert!(client.respond_protected("user", "secret\n").is_err());
        let parsed = crate::parse_challenges("Basic realm=\"camera\"").unwrap();
        let ascii = BasicClient::try_from(&parsed[0]).unwrap();
        assert!(ascii.respond_protected("test", "£").is_err());
        for value in [
            "Basic realm=\"one\", Realm=\"two\"",
            "Basic realm=\"one\",charset=\"latin1\"",
        ] {
            let parsed = crate::parse_challenges(value).unwrap();
            assert!(BasicClient::try_from(&parsed[0]).is_err());
        }
        let p = crate::PasswordParams {
            username: "private-user",
            password: "private-password",
            method: "GET",
            uri: "/",
            body: None,
        };
        assert_eq!(format!("{:?}", p), "PasswordParams([protected])");
    }
}
