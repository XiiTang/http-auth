# Boundless patches

The `boundless` branch carries these patches on upstream v0.1.10
(`4f39f8be586b7cc29c97c0bad27e73aa4534293e`). The Boundless runtime owns
transport, frozen credentials, accepted schemes and algorithms, request
dispatch and response policy; this crate owns challenge parsing, Digest nonce
counts, header construction and proof checks.

| Patch | Why | Regression |
| --- | --- | --- |
| Protected explicit Digest responses and server proof verification | Production callers use `BasicClient::respond_protected` and `DigestClient::select_qop` + `respond_protected`. `DigestResponse` owns a zeroizing Authorization value and a non-Debug `ServerProof`, which verifies `Authentication-Info` against its exact request and the response body; an optional `nextnonce` is returned, never adopted, and verification never retries, changes credentials or starts another exchange. auth-int hashes the entity body before A2; session algorithms without qop keep their algorithm and cnonce; duplicate parameters and unsupported charsets are refused and a challenge must be ASCII or declared UTF-8; UTF-8 credentials are normalized to NFC; the protected Basic entry refuses a colon in the username and control characters; `PasswordParams` Debug is redacted; nonce-count exhaustion fails without wrapping; password-derived strings and proof state are zeroized | Library tests; independent Python hashlib vectors over six algorithm/session combinations × three qop modes, binary bodies, server proofs, tampering, no implicit `nextnonce` adoption and exhausted nonce counts |
| Adopt verified next nonces without resetting an unchanged nonce | A caller that adopts a verified `nextnonce` keeps counting an unchanged one | `adopt_verified_nonce` tests |
| Preserve the Digest offer across explicit per-request qop selection | Selecting a qop for one request leaves the server's offer for the next | `select_qop` tests |
| `token68` challenges (RFC 9110 section 11.6.1) | A `Negotiate` reply carries its token as a token68 (RFC 4559), often in one field with other challenges; upstream refused the form, so a field holding one hid every challenge in it. `ChallengeRef::token68` holds it, Basic and Digest refuse a challenge carrying one, and its Debug output does not print it | `token68_stands_alone_after_its_scheme`, `token68_is_refused_where_the_grammar_has_no_room_for_it`; the fuzz target's nom reference parser reads token68 too, and 2,000,000 generated inputs over scheme, token68 and parameter fragments parsed the same through both parsers |

```sh
cargo test --all-features
```

Boundless consumes a full commit SHA; run these and the Boundless HTTP and RTSP
Digest regressions before moving the pin.
