# Controlled password authentication

Base: upstream v0.1.10. The Runtime owns transport, frozen credentials, accepted
schemes/algorithms, explicit request dispatch and response policy. This crate
owns challenge parsing, Digest nonce count, header construction and proof checks.

Production callers use `BasicClient::respond_protected` and
`DigestClient::select_qop` + `respond_protected`. DigestResponse owns a zeroizing
Authorization value and a non-Debug ServerProof. Keep the proof with its exact
request and verify Authentication-Info against the actual response body. An
optional nextnonce is returned privately; verification does not adopt it, retry
a request, change credentials or start another exchange.

The fork fixes auth-int to hash the entity body before including it in A2,
preserves the required algorithm/cnonce for session algorithms without qop,
rejects ambiguous duplicate parameters and unsupported charsets, and requires
ASCII or a declared UTF-8 challenge. UTF-8 credentials are normalized to NFC.
The protected Basic entry point rejects colon in usernames and control
characters. PasswordParams Debug is redacted. Nonce-count exhaustion fails
without wrapping. Password-derived temporary strings and proof state are owned
by zeroizing containers.

Validation: 14 library tests. Independent Python hashlib vectors cover six
algorithm/session combinations × three qop modes, binary request/response bodies,
server proof verification, tampering, no implicit nextnonce adoption and exhausted
nonce counts. Existing RFC vectors and parser tests remain. This is library
validation; RTSP Runtime/TLS/interoperability acceptance is separate.
