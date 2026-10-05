# Boundless patches

The `boundless` branch carries these patches on upstream v0.1.10
(`4f39f8be586b7cc29c97c0bad27e73aa4534293e`). The Boundless runtime owns
transport, frozen credentials, request dispatch and response policy; this
crate owns challenge parsing, the choice of a Digest challenge, nonce counts,
header construction and proof checks.

| Patch | Why | Regression |
| --- | --- | --- |
| Protected explicit Digest responses and server proof verification | Production callers use `BasicClient::respond_protected` and `DigestClient::select_qop` + `respond_protected`. `DigestResponse` owns a zeroizing Authorization value and a non-Debug `ServerProof`, which verifies `Authentication-Info` against its exact request and the response body; an optional `nextnonce` is returned, never adopted, and verification never retries, changes credentials or starts another exchange. auth-int hashes the entity body before A2; session algorithms without qop keep their algorithm and cnonce; duplicate parameters and unsupported charsets are refused and a challenge must be ASCII or declared UTF-8; UTF-8 credentials are normalized to NFC; the protected Basic entry refuses a colon in the username and control characters; `PasswordParams` Debug is redacted; nonce-count exhaustion fails without wrapping; password-derived strings and proof state are zeroized | Library tests; independent Python hashlib vectors over six algorithm/session combinations × three qop modes, binary bodies, server proofs, tampering, no implicit `nextnonce` adoption and exhausted nonce counts |
| Adopt verified next nonces without resetting an unchanged nonce | A caller that adopts a verified `nextnonce` keeps counting an unchanged one | `adopt_verified_nonce` tests |
| Preserve the Digest offer across explicit per-request qop selection | Selecting a qop for one request leaves the server's offer for the next | `select_qop` tests |
| `Authentication-Info` field lines as one list, and what a reply without qop proves | RFC 9110 section 5.3 lets a list field arrive in several lines, and RFC 7616 section 3.5 requires `rspauth` only with qop. `ServerProof::verify` takes every field line of the reply, as bytes, reads them as one list and refuses a parameter in two of them or a line that is not text; it answers `ServerInfo::Proven` with the `nextnonce` that may be adopted, or `ServerInfo::Unproven` for no field, or a field without `rspauth` when no qop was answered, whose `nextnonce` is not to be adopted. Every caller passes its lines and keeps no rule of its own | `authentication_info_lines_are_one_list`, `without_qop_a_nextnonce_alone_proves_nothing` |
| A challenge without qop offers none | Upstream reported a challenge without `qop` as offering `auth` while answering it in the RFC 2069 form, so a caller choosing by `qop()` selected `auth`, which `select_qop` then refused. `qop()` is now empty for such a challenge, which is answered with `select_qop(None)`; the response's A2 is still that of `auth` (RFC 7616 section 3.4.3) | `a_challenge_without_qop_offers_none_and_is_answered_without_one`; the RFC 2617 example vector |
| `token68` challenges (RFC 9110 section 11.6.1) | A `Negotiate` reply carries its token as a token68 (RFC 4559), often in one field with other challenges; upstream refused the form, so a field holding one hid every challenge in it. `ChallengeRef::token68` holds it, Basic and Digest refuse a challenge carrying one, and its Debug output does not print it | `token68_stands_alone_after_its_scheme`, `token68_is_refused_where_the_grammar_has_no_room_for_it`; the fuzz target's nom reference parser reads token68 too, and 2,000,000 generated inputs over scheme, token68 and parameter fragments parsed the same through both parsers |
| A Digest session across requests (RFC 7616 section 3.3) | Boundless answered HTTP and proxy challenges and the media fork RTSP ones each with its own copy of the choice of challenge, the qop and the proof check, and every fix had to land in both. `DigestSession` holds that once: `challenged` adopts the first challenge the client can answer (RFC 7616 section 3.7), passing over an unreadable one and one offering only `auth-int` unless its holder has whole bodies; `respond` answers with `auth` where offered and counts the adopted nonce, so a holder that keeps the session (RTSP, per connection) answers later requests without another 401, as curl and httpx do; `replied` checks the proof and adopts a `nextnonce` only when proven | `a_session_adopts_the_first_challenge_it_can_answer`, `a_session_counts_its_nonce_and_adopts_only_a_proven_next_one` |

```sh
cargo test --all-features
```

Boundless consumes a full commit SHA; run these and the Boundless HTTP and RTSP
Digest regressions before moving the pin.
