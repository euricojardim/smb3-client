# Functional Tri-State for `ClientOptions.signing`

**Status:** Approved design, ready for implementation plan.
**Date:** 2026-05-11
**Related:** PR #3 (encryption tri-state) established the pattern this spec mirrors.

## Motivation

`ClientOptions.signing` is currently declared as `"required" | "if-offered"` in `src/types.ts` but is **not read anywhere in `src/`**. Today, signing happens unconditionally once a session derives a key. The option is decorative.

PR #3 introduced a fully functional `encryption: "disabled" | "if-offered" | "required"` field with real semantics at each value. The new asymmetry — a working tri-state for encryption alongside an unwired two-state for signing — is a documentation hazard: users will reasonably assume both options behave the same way, and they don't.

This spec makes `signing` functional with the same shape and the same semantics where they map cleanly, so the two options compose predictably and the API stops lying.

## Goals

- Make `signing` a functional tri-state matching `encryption`'s shape.
- Preserve current behavior for callers who don't pass the option or pass `"if-offered"`.
- Compose cleanly with `encryption`, honoring the MS-SMB2 rule that an encrypted message's inner Signature field must be zero.
- Minimize diff and mirror the encryption PR's structure so the two features are reviewable as siblings.

## Non-goals

- Refactoring the encryption PR's wiring into a unified `MessageProtection` abstraction. That is a separate design.
- Fixing the other Important/Minor issues the code review flagged on PR #3 (cipher-count validation, magic numbers, error class for crypto failures, key zeroization). Those land in their own PRs.
- Per-share signing flags. The SMB2 spec defines no equivalent of `SHAREFLAG_ENCRYPT_DATA` for signing.

## API surface

```ts
// src/types.ts
export interface ClientOptions {
  // ...
  signing?: "disabled" | "if-offered" | "required";    // was: "required" | "if-offered"
  encryption?: "disabled" | "if-offered" | "required"; // unchanged
}
```

Default when undefined: `"if-offered"`. Adding `"disabled"` is purely additive — existing callers passing `"required"` or `"if-offered"` keep compiling and keep working with no behavior change.

## State semantics

| State | NEGOTIATE `SecurityMode` | Derive signing key | Outbound (non-encrypted) | Inbound (post-handshake) | NEGOTIATE-response check |
|---|---|---|---|---|---|
| `disabled` | `SIGNING_ENABLED` | Yes (still derived during auth) | Never sign | Don't require sig; tolerate unsigned | **Fail setup** if server response has `SIGNING_REQUIRED` bit set |
| `if-offered` *(default)* | `SIGNING_ENABLED` | Yes | Sign (current behavior) | Verify if signed; tolerate unsigned | None |
| `required` | `SIGNING_ENABLED \| SIGNING_REQUIRED` | Yes | Sign | **Reject** any frame that is neither signed nor encrypted | None |

### The signed-or-encrypted invariant

When `signing: "required"`, every post-handshake frame must be authenticated by either a signature OR an AEAD tag (TRANSFORM_HEADER). This matches MS-SMB2 §3.1.4.3, which mandates that an encrypted message's inner Signature field be zero — so the per-message rule "must be authenticated" is satisfied by either mechanism, but never by both.

Concretely: `signing: "required"` + `encryption: "required"` is a legal and useful combination. Encrypted frames pass with their inner Signature zero. Unencrypted frames are rejected unless signed.

### Why `disabled` still derives the signing key

NTLM/SPNEGO session-key derivation produces the signing key as a byproduct of authentication. We derive it regardless of mode so that the auth handshake itself remains spec-compliant. The mode controls whether the key is **used** for outbound signing and whether unsigned inbound frames are **tolerated** — not whether it is computed.

## Wiring

### `src/session/session.ts`

- Read `this.opts.signing ?? "if-offered"` once at the top of `setup()`. Store as `this.signingMode`.
- NEGOTIATE request:
  - Mode `"required"`: advertise `SecurityMode.SIGNING_ENABLED | SecurityMode.SIGNING_REQUIRED`.
  - Mode `"disabled"` and `"if-offered"`: advertise `SecurityMode.SIGNING_ENABLED` (current behavior).
- NEGOTIATE response check (immediately after parsing):
  - Mode `"disabled"` and response `SecurityMode` has the `SIGNING_REQUIRED` bit set → throw `SmbAuthError` with a message naming the conflict.
- SESSION_SETUP requests: `SecurityMode` field unchanged — keep advertising `SIGNING_ENABLED` since the per-session signing decision is the NEGOTIATE one.
- After verifier registration:
  - Call `this.conn.setSigningMode(this.signingMode)` so the Connection knows the inbound enforcement policy.
  - `makeSigning()` returns `undefined` when `signingMode === "disabled"`, regardless of whether a signing key was derived. This is the single switch that prevents outbound signing in `"disabled"` mode without changing any caller of `makeSigning()`.

### `src/connection/connection.ts`

- Add private field `signingMode: "disabled" | "if-offered" | "required" = "if-offered"`.
- Add setter `setSigningMode(mode)` parallel to the existing `setEncryptionRequired(flag)`.
- Outbound path (the existing `if (opts.signing) { ... sign ... }` block around line 142): **no change required**. Because `Session.makeSigning()` already returns `undefined` for `"disabled"`, `opts.signing` will be absent and the block is naturally skipped.
- Inbound path (next to the existing plaintext-after-encryption-required check around line 222):
  - Add a parallel check: if `signingMode === "required"` and the frame is neither encrypted (TRANSFORM_HEADER) nor signed (header `SIGNED` flag set and a non-zero Signature), reject and close the connection. Exempt: pre-auth window (NEGOTIATE response and first SESSION_SETUP response) — reuse the same exemption flag the encryption check uses.

### Caller surface

No call-site changes outside `session.ts` and `connection.ts`. All the `open/*.ts`, `tree.ts`, and `client.ts` call sites already consume `Session.makeSigning()` and will naturally stop signing when the mode is `"disabled"`.

## Pre-auth and edge cases

- **Pre-auth frames** (NEGOTIATE, first SESSION_SETUP request/response): unsigned and unencrypted by definition of the handshake. The existing pre-auth tracker in `connection.ts` already exempts these from the encryption-required rejection. Reuse that same flag for the signing-required rejection. No new state.
- **CANCEL frames**: existing logic at `connection.ts:300-336` inherits the protected frame's mode (sign if signed, encrypt if encrypted). Under `signing: "disabled"`, CANCELs go out unsigned. Some Windows configurations may reject this per MS-SMB2 §3.2.4.24, but that is consistent with the user's explicit choice to disable signing.
- **LOGOFF / TREE_DISCONNECT under `disabled`**: sent unsigned. Compatible with servers that allow unsigned sessions.
- **`signing: "disabled"` + `encryption: "required"`**: legal and useful — confidentiality-only.
- **`signing: "required"` + `encryption: "disabled"`**: legal — integrity-only, every post-auth frame must carry an SMB2 signature.
- **`signing: "disabled"` + `encryption: "disabled"`**: legal but a footgun. Documented in README and `SECURITY.md` as not recommended outside test environments.
- **`signing: "required"` against a server that does not support signing**: server's NEGOTIATE response will not contain a usable security mode and signing-key derivation will not produce a usable key for the dialect; setup fails. In practice every SMB2-capable server supports signing, so this path is mostly theoretical.

## Tests

Mirror the encryption test files:

- `test/unit/session/signing-mode.test.ts`
  - Mode `"required"` causes NEGOTIATE request to advertise `SIGNING_ENABLED | SIGNING_REQUIRED`.
  - Mode `"disabled"` causes NEGOTIATE request to advertise only `SIGNING_ENABLED`.
  - Mode `"disabled"` + server response with `SIGNING_REQUIRED` bit → throws.
  - Mode `"if-offered"` (and undefined) preserves current `SIGNING_ENABLED`-only behavior.

- `test/unit/connection/connection.signing.test.ts`
  - Outbound: `"disabled"` does not sign even when a session key would be available.
  - Outbound: `"required"` signs every post-handshake non-encrypted frame.
  - Inbound: `"required"` rejects an unsigned, unencrypted frame after pre-auth.
  - Inbound: `"required"` accepts an encrypted-only frame (signed-or-encrypted invariant).
  - Pre-auth exemption: `"required"` accepts the NEGOTIATE response and the first SESSION_SETUP response without a signature.

- `test/unit/connection/connection.encryption.test.ts` (extend)
  - One combined-mode test: `signing: "required"` + `encryption: "required"` — encrypted-and-unsigned frames pass; unencrypted-and-unsigned frames are rejected.

## Documentation

- `README.md` (around line 102-103): document `signing: "disabled" | "if-offered" | "required"` with parallel prose to the `encryption` block. Note the default.
- `SECURITY.md`: add a paragraph on the `signing: "disabled"` and `encryption: "disabled"` combinations, framing them as test-only.
- `docs/superpowers/specs/2026-05-09-node-smb3-client-design.md`: append a short note that signing is now functionally tri-state, matching encryption.

## Out of scope

- `selectCipher` cipher-count validation (code review Important #4 on PR #3).
- Magic-number cleanup in `session.ts:217` (PR #3 review Important #6).
- Dedicated `SmbCryptoError` class instead of `SmbProtocolError({ status: 0 })` (PR #3 review Minor #8).
- Key zeroization on session close (PR #3 review Minor #9).
- `MessageProtection` abstraction unifying the two policies (Approach B from the brainstorm).

## Acceptance criteria

- All three values of `signing` produce the documented behavior in unit tests.
- Existing callers passing nothing, `"if-offered"`, or `"required"` see no behavior change from today (since today's de facto behavior is `"if-offered"`-equivalent, and `"required"` adds enforcement that current callers already satisfy by always signing).
- Combined-mode test passes: `signing: "required"` + `encryption: "required"` works against the test fixtures, with encrypted frames having zero Signature in the inner header.
- README and SECURITY.md updated.
- No changes outside `session.ts`, `connection.ts`, `types.ts`, the new test files, README, and SECURITY.md.
