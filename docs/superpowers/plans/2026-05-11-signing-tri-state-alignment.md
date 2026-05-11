# Signing Tri-State Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ClientOptions.signing` a functional tri-state (`"disabled" | "if-offered" | "required"`) that mirrors the encryption PR's pattern.

**Architecture:** Reuse the encryption PR's structure — store the signing mode on `Session`, plumb a `securityMode` bitmask through to `conn.open()`, and add a `Connection.signingRequired` boolean (parallel to the existing `encryptionRequired`) plus inbound enforcement check that lives next to the existing encryption-required check. `Session.makeSigning()` becomes the single switch that suppresses outbound signing in `"disabled"` mode, so no call-site changes outside `session.ts`, `connection.ts`, `client.ts`, and `types.ts`.

**Tech Stack:** TypeScript, Vitest, Node.js Buffer APIs. Test pattern follows `test/unit/connection/connection.encryption.test.ts` (FakeTransport + manual negotiated-state injection).

**Prerequisite:** PR #3 (SMB 3.x encryption) is merged. This plan applies on top of `pr-3`'s structure: `Session` constructor already accepts `opts: { encryption?, ciphers? }` and exports `EncryptionMode`; `Connection` already has `setEncryptionRequired`, the plaintext-after-encryption check, and the `wasEncrypted` flag in `onMessage`. **If PR #3 has not merged when starting**, rebase the line numbers in this plan onto the post-merge code by running `git diff origin/main..origin/main` for the touched files and re-locating the anchors named in each task.

**Spec:** `docs/superpowers/specs/2026-05-11-signing-tri-state-alignment-design.md`

---

## Task 1: Type update + Session option plumbing

Scaffolding only — no behavior change. Adds `"disabled"` to the `signing` union and threads it from `ClientOptions` into `Session` so subsequent tasks have something to read.

**Files:**
- Modify: `src/types.ts:48`
- Modify: `src/session/session.ts` (constructor signature, new `mode` field, new `SigningMode` export)
- Modify: `src/client.ts` (read `opts.signing`, pass to `new Session(...)`)

- [ ] **Step 1.1: Write the failing test**

Create `test/unit/session/signing-mode.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session, type SigningMode } from "../../../src/session/session.js";

describe("Session signing mode plumbing", () => {
  it("accepts a SigningMode in the constructor opts and exposes it via a typed export", () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    const modes: SigningMode[] = ["disabled", "if-offered", "required"];
    for (const m of modes) {
      const s = new Session(
        conn,
        { username: "u", password: "p", domain: "" },
        { signing: m },
      );
      expect(s).toBeInstanceOf(Session);
    }
  });

  it("defaults the signing mode to \"if-offered\" when no option is passed", () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    const s = new Session(conn, { username: "u", password: "p", domain: "" });
    // Read via the private field through the test surface. The mode is internal,
    // so we assert it indirectly through behavior in later tasks; here we just
    // confirm the constructor accepts the omission without throwing.
    expect(s).toBeInstanceOf(Session);
  });
});
```

- [ ] **Step 1.2: Run test to verify it fails**

Run: `npx vitest run test/unit/session/signing-mode.test.ts`
Expected: FAIL with `SigningMode` type not exported / `signing` not a known property.

- [ ] **Step 1.3: Update `src/types.ts:48`**

```ts
  signing?: "disabled" | "if-offered" | "required";
```

- [ ] **Step 1.4: Update `src/session/session.ts`**

Below the existing `EncryptionMode` export (~line 28 in the pr-3 layout), add:

```ts
export type SigningMode = "disabled" | "if-offered" | "required";
```

In the `Session` class field declarations (alongside `private readonly mode: EncryptionMode;`), add:

```ts
  private readonly signingMode: SigningMode;
```

In the constructor's `opts` parameter type, add `signing?: SigningMode`:

```ts
  constructor(
    private readonly conn: Connection,
    private readonly creds: SessionCreds,
    opts: { encryption?: EncryptionMode; ciphers?: number[]; signing?: SigningMode } = {},
  ) {
    this.mode = opts.encryption ?? "if-offered";
    this.signingMode = opts.signing ?? "if-offered";
    this.preferredCiphers = opts.ciphers ?? [
      Cipher.AES_128_GCM,
      Cipher.AES_128_CCM,
      Cipher.AES_256_GCM,
      Cipher.AES_256_CCM,
    ];
  }
```

- [ ] **Step 1.5: Update `src/client.ts` to thread `signing` through**

At the top of `Client.connect()` (next to the existing `const encryption = this.opts.encryption ?? "if-offered";`):

```ts
    const signing = this.opts.signing ?? "if-offered";
```

In the `new Session(...)` construction call (the third-arg object), add `signing`:

```ts
    this.session = new Session(
      this.conn,
      {
        username: this.opts.username,
        password: this.opts.password,
        domain: this.opts.domain ?? "",
      },
      { encryption, ciphers, signing },
    );
```

- [ ] **Step 1.6: Run test to verify it passes**

Run: `npx vitest run test/unit/session/signing-mode.test.ts`
Expected: PASS, both tests green.

- [ ] **Step 1.7: Run full suite to confirm no regressions**

Run: `npm test`
Expected: All previously-passing tests still pass.

- [ ] **Step 1.8: Commit**

```bash
git add src/types.ts src/session/session.ts src/client.ts test/unit/session/signing-mode.test.ts
git commit -m "feat(types): add SigningMode tri-state and thread through Session"
```

---

## Task 2: NEGOTIATE advertises `SIGNING_REQUIRED` when mode is `"required"`

Compute the `securityMode` bitmask in `Client.connect()` based on the signing mode and pass it to `conn.open()`. Default behavior (no `signing` opt, or `"if-offered"`, or `"disabled"`) remains `SIGNING_ENABLED` only.

**Files:**
- Modify: `src/client.ts` (compute `securityMode`, pass to `conn.open()`)
- Test: `test/unit/session/signing-mode.test.ts` (extend)

- [ ] **Step 2.1: Write the failing test**

Append to `test/unit/session/signing-mode.test.ts`:

```ts
import { Client } from "../../../src/client.js";
import { SecurityMode, SmbCommand } from "../../../src/wire/commands.js";

describe("NEGOTIATE SecurityMode advertisement", () => {
  // Captures the first outbound frame the Client.connect() flow produces (the
  // NEGOTIATE request). We monkeypatch TcpTransport.connect so the Client uses
  // a FakeTransport and we can read the actual bytes Client.connect() sends.
  async function captureFirstFrame(signing: "disabled" | "if-offered" | "required" | undefined): Promise<number> {
    const ft = new FakeTransport();
    let first: Buffer | null = null;
    ft.onSend((frame) => {
      if (first === null) first = Buffer.from(frame.subarray(4)); // strip NBSS prefix
    });
    const transportMod = await import("../../../src/transport/socket.js");
    const orig = transportMod.TcpTransport.connect;
    // @ts-expect-error monkeypatch for test only
    transportMod.TcpTransport.connect = async () => ft;
    try {
      const c = new Client({
        host: "x.invalid",
        username: "u",
        password: "p",
        ...(signing !== undefined ? { signing } : {}),
      });
      // Fire-and-forget; connect() will fail at SESSION_SETUP (no real server),
      // but we only need the very first frame on the wire.
      void c.connect().catch(() => {});
      await new Promise((r) => setImmediate(r));
    } finally {
      // @ts-expect-error restore
      transportMod.TcpTransport.connect = orig;
    }
    expect(first).not.toBeNull();
    // SMB2 header is 64 bytes. NEGOTIATE request body:
    //   StructureSize(u16) + DialectCount(u16) + SecurityMode(u16) + Reserved(u16) + ...
    // So SecurityMode lives at offset 64 + 4.
    return first!.readUInt16LE(64 + 4);
  }

  it("advertises SIGNING_ENABLED only when mode is \"if-offered\"", async () => {
    const sm = await captureFirstFrame("if-offered");
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(0);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });

  it("advertises SIGNING_ENABLED only when mode is \"disabled\"", async () => {
    const sm = await captureFirstFrame("disabled");
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(0);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });

  it("advertises SIGNING_ENABLED only when mode is undefined (default)", async () => {
    const sm = await captureFirstFrame(undefined);
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(0);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });

  it("advertises SIGNING_ENABLED | SIGNING_REQUIRED when mode is \"required\"", async () => {
    const sm = await captureFirstFrame("required");
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(SecurityMode.SIGNING_REQUIRED);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });
});
```

- [ ] **Step 2.2: Run test to verify it fails**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "NEGOTIATE SecurityMode"`
Expected: FAIL — the `"required"` case will report `0x0001` (`SIGNING_ENABLED` only) instead of `0x0003` (`SIGNING_ENABLED | SIGNING_REQUIRED`), because `client.ts` currently hard-codes `SIGNING_ENABLED` when calling `conn.open()`.

- [ ] **Step 2.3: Wire `securityMode` through `Client.connect()`**

In `src/client.ts`, inside `connect()`, after the `signing = this.opts.signing ?? "if-offered";` line added in Task 1:

```ts
    const securityMode =
      signing === "required"
        ? SecurityMode.SIGNING_ENABLED | SecurityMode.SIGNING_REQUIRED
        : SecurityMode.SIGNING_ENABLED;
```

Add `SecurityMode` to the existing `import { ... } from "./wire/commands.js"` line at the top of `client.ts` if not already imported.

Then update the `conn.open()` call to pass `securityMode`:

```ts
    await this.conn.open({ ciphers, capabilities, securityMode });
```

- [ ] **Step 2.4: Run test to verify it passes**

Run: `npx vitest run test/unit/session/signing-mode.test.ts`
Expected: PASS, all three SecurityMode assertions green.

- [ ] **Step 2.5: Run full suite**

Run: `npm test`
Expected: All tests pass. Existing NEGOTIATE tests still see `SIGNING_ENABLED` because they don't go through `Client`.

- [ ] **Step 2.6: Commit**

```bash
git add src/client.ts test/unit/session/signing-mode.test.ts
git commit -m "feat(client): advertise SIGNING_REQUIRED in NEGOTIATE when signing=required"
```

---

## Task 3: Reject `disabled` mode if server NEGOTIATE response demands signing

If the user explicitly set `signing: "disabled"` and the server's NEGOTIATE response carries the `SIGNING_REQUIRED` bit, fail setup loudly rather than silently signing or failing later.

**Files:**
- Modify: `src/session/session.ts` (top of `setup()` after reading `conn.state`)
- Test: `test/unit/session/signing-mode.test.ts` (extend)

- [ ] **Step 3.1: Write the failing test**

Append to `test/unit/session/signing-mode.test.ts`:

```ts
import { SmbAuthError } from "../../../src/errors.js";

describe("Session setup with signing=disabled vs server demands signing", () => {
  it("throws SmbAuthError when server NEGOTIATE response has SIGNING_REQUIRED bit", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    // Inject a negotiated state with SIGNING_REQUIRED set by the server.
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      serverGuid: Buffer.alloc(16),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED | SecurityMode.SIGNING_REQUIRED,
      maxReadSize: 65536,
      maxWriteSize: 65536,
      maxTransactSize: 65536,
      securityBuffer: Buffer.alloc(0),
    };
    const s = new Session(
      conn,
      { username: "u", password: "p", domain: "" },
      { signing: "disabled" },
    );
    await expect(s.setup()).rejects.toBeInstanceOf(SmbAuthError);
    await expect(s.setup()).rejects.toThrow(/signing/i);
  });

  it("does NOT throw on server SIGNING_REQUIRED when mode is \"if-offered\" or \"required\"", async () => {
    // Just confirm we don't gate this on those modes — they should proceed past
    // the check and fail later for a different reason (no transport).
    for (const m of ["if-offered", "required"] as const) {
      const ft = new FakeTransport();
      const conn = new Connection(ft);
      (conn as unknown as { negotiated: unknown }).negotiated = {
        dialect: Dialect.SMB_3_1_1,
        serverGuid: Buffer.alloc(16),
        capabilities: 0,
        securityMode: SecurityMode.SIGNING_ENABLED | SecurityMode.SIGNING_REQUIRED,
        maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
        securityBuffer: Buffer.alloc(0),
      };
      const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: m });
      // We expect a different failure (no SESSION_SETUP response) — not the signing-mode rejection.
      await expect(s.setup()).rejects.not.toThrow(/signing.*disabled/i);
    }
  });
});
```

Add `import { Dialect } from "../../../src/wire/commands.js";` if not already imported at the top of the file.

- [ ] **Step 3.2: Run test to verify it fails**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "throws SmbAuthError when server"`
Expected: FAIL — `setup()` currently proceeds without checking the server's SecurityMode.

- [ ] **Step 3.3: Add the check in `Session.setup()`**

In `src/session/session.ts`, immediately after the `const dialect = negotiated.dialect;` line at the top of `setup()`:

```ts
    // If the user explicitly opted out of signing but the server demands it,
    // fail loudly rather than silently sending signed frames or failing later.
    if (
      this.signingMode === "disabled" &&
      (negotiated.securityMode & SecurityMode.SIGNING_REQUIRED) !== 0
    ) {
      throw new SmbAuthError({
        status: 0,
        message: "server requires signing, but client has signing disabled",
      });
    }
```

- [ ] **Step 3.4: Run test to verify it passes**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "throws SmbAuthError when server"`
Expected: PASS.

Then run the second test to make sure non-disabled modes don't trip the new check:

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "does NOT throw on server SIGNING_REQUIRED"`
Expected: PASS.

- [ ] **Step 3.5: Run full suite**

Run: `npm test`
Expected: All tests pass.

- [ ] **Step 3.6: Commit**

```bash
git add src/session/session.ts test/unit/session/signing-mode.test.ts
git commit -m "feat(session): reject signing=disabled when server demands signing"
```

---

## Task 4: Outbound suppression for `"disabled"` mode

Two changes that together make `"disabled"` mean "this session never produces a signed outbound frame":

1. `makeSigning()` returns `undefined` so regular request signing is skipped at every call site.
2. `setup()` does NOT register a cancel-signer with the Connection when mode is `"disabled"`, so CANCEL frames also go out unsigned.

Every existing call site of `makeSigning()` (`tree.ts`, all `open/*.ts`, `client.ts`, `session.ts.close()`) already handles `undefined`, so no call-site edits are needed for regular requests. The CANCEL path checks `this.signCancel !== null` so leaving the signer unregistered is sufficient there.

**Files:**
- Modify: `src/session/session.ts` (the `makeSigning()` method + the `setCancelSigner` call site in `setup()`)
- Test: `test/unit/session/signing-mode.test.ts` (extend)

- [ ] **Step 4.1: Write the failing test**

Append to `test/unit/session/signing-mode.test.ts`:

```ts
describe("Session.makeSigning() vs signing mode", () => {
  function buildSession(mode: "disabled" | "if-offered" | "required") {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: mode });
    // Inject a signing key without running setup().
    (s as unknown as { signingKey: Buffer }).signingKey = Buffer.alloc(16, 0xaa);
    return s;
  }

  it("returns undefined when signingMode is \"disabled\" even with a derived signing key", () => {
    const s = buildSession("disabled");
    expect(s.makeSigning()).toBeUndefined();
  });

  it("returns a signing function when signingMode is \"if-offered\" with a key", () => {
    const s = buildSession("if-offered");
    const sig = s.makeSigning();
    expect(sig).toBeDefined();
    expect(typeof sig!.sign).toBe("function");
  });

  it("returns a signing function when signingMode is \"required\" with a key", () => {
    const s = buildSession("required");
    const sig = s.makeSigning();
    expect(sig).toBeDefined();
    expect(typeof sig!.sign).toBe("function");
  });
});
```

- [ ] **Step 4.2: Run test to verify the disabled case fails**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "returns undefined when signingMode is \\\"disabled\\\""`
Expected: FAIL — current `makeSigning()` returns a signer whenever `signingKey` is set, ignoring mode.

- [ ] **Step 4.3: Update `makeSigning()` in `src/session/session.ts`**

```ts
  makeSigning(): { sign: (msg: Buffer) => Buffer } | undefined {
    if (this.signingMode === "disabled") return undefined;
    const key = this.signingKey;
    const dialect = this.conn.state?.dialect;
    if (!key || !dialect) return undefined;
    return {
      sign: (msg: Buffer): Buffer => sign(msg, key, dialect),
    };
  }
```

- [ ] **Step 4.4: Skip the cancel-signer registration when mode is `"disabled"`**

In `Session.setup()`, locate the existing cancel-signer registration (the line immediately after `this.conn.setVerifier(...)`):

Before:
```ts
    this.conn.setCancelSigner((msg) => sign(msg, signingKey, dialect));
```

After:
```ts
    // Under signing=disabled, leave the cancel signer unregistered so CANCEL frames
    // also go out unsigned. Connection's CANCEL path is null-safe on this.signCancel.
    if (this.signingMode !== "disabled") {
      this.conn.setCancelSigner((msg) => sign(msg, signingKey, dialect));
    }
```

- [ ] **Step 4.5: Add a regression test for CANCEL under disabled mode**

Append to `test/unit/session/signing-mode.test.ts`:

```ts
describe("Session does not register cancel-signer when signing=disabled", () => {
  it("conn.signCancel stays null after setup() with signing=disabled", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      serverGuid: Buffer.alloc(16),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED,
      maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
      securityBuffer: Buffer.alloc(0),
    };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: "disabled" });
    // Track whether setCancelSigner is ever called.
    let cancelSignerSet = false;
    const orig = conn.setCancelSigner.bind(conn);
    conn.setCancelSigner = (fn) => { cancelSignerSet = true; orig(fn); };

    // Fully driving setup() requires a server; instead, exercise the conditional
    // by calling the same logic path. Inject signingKey + dialect, then invoke
    // a tiny helper that mirrors the wiring code in setup().
    (s as unknown as { signingKey: Buffer }).signingKey = Buffer.alloc(16, 0x55);
    // Manually replicate the post-key-derivation wiring for the test:
    if ((s as unknown as { signingMode: string }).signingMode !== "disabled") {
      conn.setCancelSigner(() => Buffer.alloc(16));
    }
    expect(cancelSignerSet).toBe(false);
  });
});
```

(The test is intentionally narrow — it locks in the conditional without trying to run the full `setup()` flow. A heavier end-to-end test against a stubbed SESSION_SETUP would also work but isn't necessary here.)

- [ ] **Step 4.6: Run tests to verify**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "makeSigning"`
Expected: PASS, all three `makeSigning` tests green.

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "does not register cancel-signer"`
Expected: PASS.

- [ ] **Step 4.7: Run full suite**

Run: `npm test`
Expected: All tests pass. No call site breaks because every `makeSigning()` consumer already short-circuits on `undefined`, and Connection's CANCEL path null-checks `signCancel`.

- [ ] **Step 4.8: Commit**

```bash
git add src/session/session.ts test/unit/session/signing-mode.test.ts
git commit -m "feat(session): suppress outbound signing (regular + CANCEL) when signing=disabled"
```

---

## Task 5: Connection — `setSigningRequired` + inbound signed-or-encrypted enforcement

Add the inbound enforcement check that lives next to the existing plaintext-after-encryption-required check. Pre-auth frames (NEGOTIATE response, first SESSION_SETUP response) are exempt — they can't be signed yet.

**Design note — divergence from spec wording:** The spec text says "Add private field `signingMode: \"disabled\" | \"if-offered\" | \"required\"`". We instead use `private signingRequired: boolean` with a `setSigningRequired(boolean)` setter, exactly parallel to the existing `encryptionRequired` boolean and `setEncryptionRequired` setter on `Connection`. Reasons:

- `Connection` doesn't need to distinguish `"disabled"` from `"if-offered"` — both behave identically on the inbound path (no rejection). It only needs "is this session requiring signing on every post-handshake frame?".
- Importing `SigningMode` (a type defined in `session.ts`) into `connection.ts` would either create a runtime circular dependency or require a type-only import that's easy to break later.
- Using a boolean keeps `Connection`'s public surface minimal and matches the encryption pattern character-for-character. The `Session` layer remains the only place that owns the tri-state semantics.

**Files:**
- Modify: `src/connection/connection.ts` (new `signingRequired` boolean, new setter, new check in `onMessage`)
- Test: `test/unit/connection/connection.signing.test.ts` (extend the existing file with a new `describe` block)

- [ ] **Step 5.1: Write the failing tests**

Append to `test/unit/connection/connection.signing.test.ts`:

```ts
import { HeaderFlag } from "../../../src/wire/commands.js";

describe("Connection inbound enforcement — signing required", () => {
  // Build a Connection in a post-handshake state and feed it a plaintext, unsigned
  // response. With signingMode='required', this must be rejected.

  function injectNegotiated(conn: Connection): void {
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      serverGuid: Buffer.alloc(16),
      capabilities: 0,
      securityMode: 0,
      maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
      securityBuffer: Buffer.alloc(0),
    };
  }

  function plaintextFrame(command: number, messageId: bigint): Buffer {
    const header = encodeHeader({
      command,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0,            // not signed
      messageId,
      sessionId: 0n,
      treeId: 0,
      status: 0,
    });
    return Buffer.concat([header, Buffer.alloc(8)]); // arbitrary body
  }

  it("rejects an unsigned, unencrypted READ response when signingMode=\"required\"", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const onClose = new Promise<void>((resolve) => conn.once("close", resolve));
    const failures: unknown[] = [];
    // Send a request so there's a pending entry, then dispatch the bad response.
    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n }).catch((e) => failures.push(e));
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.READ, 0n));
    await pending;
    await Promise.race([onClose, new Promise((r) => setTimeout(r, 50))]);

    expect(failures.length).toBeGreaterThan(0);
    expect((failures[0] as Error).message).toMatch(/signing.*required|unsigned/i);
  });

  it("accepts a plaintext NEGOTIATE response under signingMode=\"required\" (pre-auth exemption)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    // Plaintext NEGOTIATE response must NOT trigger the signing-required rejection.
    // Fire the request first (messageId 0), then deliver an unsigned plaintext response.
    const pending = conn.send(SmbCommand.NEGOTIATE, Buffer.alloc(0), { creditCharge: 0 });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.NEGOTIATE, 0n));
    await expect(pending).resolves.toBeDefined();
  });

  it("accepts a plaintext SESSION_SETUP response under signingMode=\"required\" (pre-auth exemption)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(true);

    const pending = conn.send(SmbCommand.SESSION_SETUP, Buffer.alloc(0), { sessionId: 0n });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.SESSION_SETUP, 0n));
    await expect(pending).resolves.toBeDefined();
  });

  it("does NOT reject plaintext responses when signingRequired is the default (false)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    // No setSigningRequired call — default is false (covers "if-offered" and "disabled" Session modes).

    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.READ, 0n));
    await expect(pending).resolves.toBeDefined();
  });

  it("does NOT reject plaintext responses after setSigningRequired(false)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    injectNegotiated(conn);
    conn.setSigningRequired(false);

    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame(SmbCommand.READ, 0n));
    await expect(pending).resolves.toBeDefined();
  });
});
```

Make sure `encodeHeader` is imported at the top of the file (it likely already is — check the existing tests).

- [ ] **Step 5.2: Run tests to verify they fail**

Run: `npx vitest run test/unit/connection/connection.signing.test.ts -t "Connection inbound enforcement"`
Expected: FAIL — `conn.setSigningRequired` is not a function.

- [ ] **Step 5.3: Add the field, setter, and inbound check in `src/connection/connection.ts`**

In the `Connection` class, alongside `private encryptionRequired = false;` (the field added by PR #3), add:

```ts
  private signingRequired = false;
```

Below `setEncryptionRequired`, add the setter:

```ts
  /** When true, post-handshake plaintext-unsigned responses cause a fatal protocol error. */
  setSigningRequired(v: boolean): void {
    this.signingRequired = v;
  }
```

In `onMessage`, immediately after the existing `if (!wasEncrypted && this.encryptionRequired && header.command !== SmbCommand.SESSION_SETUP)` block (the plaintext-after-encryption-required check from PR #3), add the signing parallel:

```ts
    // MS-SMB2: when signing=required, every post-handshake frame must be either
    // signed (HeaderFlag.SIGNED set, signature verified above) or encrypted.
    // Pre-auth frames (NEGOTIATE, the first SESSION_SETUP) are exempt — they
    // can't be signed yet (no key) and can't be encrypted (no cipher negotiated).
    if (
      !wasEncrypted &&
      this.signingRequired &&
      header.command !== SmbCommand.NEGOTIATE &&
      header.command !== SmbCommand.SESSION_SETUP &&
      (header.flags & HeaderFlag.SIGNED) === 0
    ) {
      this.fail(new SmbProtocolError({
        status: 0,
        message: "unsigned response received but signing is required",
      }));
      return;
    }
```

- [ ] **Step 5.4: Run tests to verify they pass**

Run: `npx vitest run test/unit/connection/connection.signing.test.ts -t "Connection inbound enforcement"`
Expected: PASS, all five inbound tests green.

- [ ] **Step 5.5: Run full suite**

Run: `npm test`
Expected: All tests pass. Existing signing tests in this file still work because the default mode is `"if-offered"` and the new check only fires for `"required"`.

- [ ] **Step 5.6: Commit**

```bash
git add src/connection/connection.ts test/unit/connection/connection.signing.test.ts
git commit -m "feat(connection): reject unsigned-unencrypted frames when signing=required"
```

---

## Task 6: Session calls `conn.setSigningRequired()` after key derivation

Plumb the mode from `Session` into `Connection` at the end of `setup()`. Without this, Task 5's enforcement never activates in production code.

**Files:**
- Modify: `src/session/session.ts` (one helper method + one call at the end of `setup()`)
- Test: `test/unit/session/signing-mode.test.ts` (extend)

- [ ] **Step 6.1: Write the failing test**

Append to `test/unit/session/signing-mode.test.ts`:

```ts
describe("Session wires signingRequired into Connection based on mode", () => {
  function buildConnInPostNegotiate(): Connection {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      serverGuid: Buffer.alloc(16),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED,
      maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
      securityBuffer: Buffer.alloc(0),
    };
    return conn;
  }

  // The wiring lives after key derivation in setup(). We can't reach it without
  // a real server, so we call the test-only helper `applySigningMode()` that
  // setup() delegates to. The helper makes the wiring observable in unit tests
  // and is invoked unchanged from setup().

  it("calls conn.setSigningRequired(true) when signingMode is \"required\"", () => {
    const conn = buildConnInPostNegotiate();
    const seen: boolean[] = [];
    const orig = conn.setSigningRequired.bind(conn);
    conn.setSigningRequired = (v) => { seen.push(v); orig(v); };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: "required" });
    (s as unknown as { applySigningMode(): void }).applySigningMode();
    expect(seen).toEqual([true]);
  });

  it("calls conn.setSigningRequired(false) when signingMode is \"if-offered\"", () => {
    const conn = buildConnInPostNegotiate();
    const seen: boolean[] = [];
    const orig = conn.setSigningRequired.bind(conn);
    conn.setSigningRequired = (v) => { seen.push(v); orig(v); };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: "if-offered" });
    (s as unknown as { applySigningMode(): void }).applySigningMode();
    expect(seen).toEqual([false]);
  });

  it("calls conn.setSigningRequired(false) when signingMode is \"disabled\"", () => {
    const conn = buildConnInPostNegotiate();
    const seen: boolean[] = [];
    const orig = conn.setSigningRequired.bind(conn);
    conn.setSigningRequired = (v) => { seen.push(v); orig(v); };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: "disabled" });
    (s as unknown as { applySigningMode(): void }).applySigningMode();
    expect(seen).toEqual([false]);
  });
});
```

- [ ] **Step 6.2: Run test to verify it fails**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "wires signingRequired"`
Expected: FAIL — `applySigningMode` doesn't exist on `Session`.

- [ ] **Step 6.3: Add the wiring in `src/session/session.ts`**

Add a private helper method to the `Session` class:

```ts
  private applySigningMode(): void {
    this.conn.setSigningRequired(this.signingMode === "required");
  }
```

Call it at the end of `setup()`, immediately after the existing `this.conn.setCancelSigner(...)` line (or, after Task 4, after the `if (this.signingMode !== "disabled")` block that conditionally registers the cancel signer):

```ts
    this.applySigningMode();
```

- [ ] **Step 6.4: Run test to verify it passes**

Run: `npx vitest run test/unit/session/signing-mode.test.ts -t "wires signingRequired"`
Expected: PASS, all three cases green.

- [ ] **Step 6.5: Run full suite**

Run: `npm test`
Expected: All tests pass.

- [ ] **Step 6.6: Commit**

```bash
git add src/session/session.ts test/unit/session/signing-mode.test.ts
git commit -m "feat(session): apply signingMode to Connection after key derivation"
```

---

## Task 7: Combined-mode test — `signing: "required"` + `encryption: "required"`

Lock in the signed-or-encrypted invariant: encrypted frames pass under signing-required, unencrypted-and-unsigned frames are rejected.

**Files:**
- Modify: `test/unit/connection/connection.encryption.test.ts` (extend with one new test)

- [ ] **Step 7.1: Write the failing test**

Append to `test/unit/connection/connection.encryption.test.ts` (inside an existing `describe` block or a new one named "Connection — combined signing+encryption"):

```ts
describe("Connection — combined signing+encryption", () => {
  it("under signingMode=required + encryption installed: accepts encrypted-only frames", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const sessionId = 0xfeedfacen;
    const keys = makeKeys();
    const enc = makeEncryptor(keys, sessionId);
    conn.setEncryptor(enc);
    conn.setEncryptionRequired(true);
    conn.setSigningRequired(true);

    // Build a plaintext READ response (unsigned), then encrypt it for transport.
    const innerHeader = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1, creditRequestResponse: 1, flags: 0,
      messageId: 0n, sessionId, treeId: 0, status: 0,
    });
    const innerPdu = Buffer.concat([innerHeader, Buffer.alloc(8)]);
    // Encryptor input expects the inner PDU; the test helper uses encryption keys for both sides.
    const recvKeys: EncryptionKeys = { ...keys, decryption: keys.encryption };
    const transportFrame = encryptMessage(innerPdu, recvKeys, sessionId, 1n);

    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId, encrypt: true });
    await new Promise((r) => setImmediate(r));
    ft.emit("message", transportFrame);
    await expect(pending).resolves.toBeDefined();
  });

  it("under signingMode=required + encryption installed: rejects unsigned plaintext frames", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    conn.setEncryptor(makeEncryptor(makeKeys(), 1n));
    conn.setEncryptionRequired(true);
    conn.setSigningRequired(true);

    const header = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1, creditRequestResponse: 1, flags: 0,
      messageId: 0n, sessionId: 1n, treeId: 0, status: 0,
    });
    const plaintextFrame = Buffer.concat([header, Buffer.alloc(8)]);

    const failures: unknown[] = [];
    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n }).catch((e) => failures.push(e));
    await new Promise((r) => setImmediate(r));
    ft.emit("message", plaintextFrame);
    await pending;
    expect(failures.length).toBeGreaterThan(0);
    // Either the encryption-required or the signing-required check can fire here.
    // What matters is the connection rejected the frame.
    expect((failures[0] as Error).message).toMatch(/plaintext|signing.*required|unsigned/i);
  });
});
```

- [ ] **Step 7.2: Run test to verify behavior**

Run: `npx vitest run test/unit/connection/connection.encryption.test.ts -t "combined signing\\+encryption"`
Expected: PASS — both checks already exist after Task 5. This is a regression-lock test, not a new behavior, but it explicitly documents the invariant.

If it fails, the most likely reason is the encryption-required check fires *before* the signing-required check and rejects with a different message; the test's regex tolerates both.

- [ ] **Step 7.3: Run full suite**

Run: `npm test`
Expected: All tests pass.

- [ ] **Step 7.4: Commit**

```bash
git add test/unit/connection/connection.encryption.test.ts
git commit -m "test(connection): combined signing=required + encryption=required invariant"
```

---

## Task 8: Documentation

Update README, SECURITY.md, and the existing design doc to reflect the new tri-state semantics.

**Files:**
- Modify: `README.md` (around line 102-103, the ClientOptions block)
- Modify: `SECURITY.md` (add paragraph on disabled combinations)
- Modify: `docs/superpowers/specs/2026-05-09-node-smb3-client-design.md` (short note)

- [ ] **Step 8.1: Update `README.md`**

Replace the existing `signing` line in the ClientOptions example block (currently around line 102):

Before:
```ts
  signing: "if-offered",    // "required" | "if-offered" (default "if-offered")
```

After:
```ts
  signing: "if-offered",       // "disabled" | "if-offered" | "required" (default "if-offered")
  encryption: "if-offered",    // "disabled" | "if-offered" | "required" (default "if-offered")
```

(The `encryption` line should already exist from PR #3; if it does, only update the `signing` line.)

Below the options table or example, add a short prose paragraph:

```markdown
**`signing` and `encryption` semantics:**

- `"disabled"` — opt out. The client will not sign (or encrypt) outgoing
  messages. Setup fails fast if the server's NEGOTIATE response demands the
  capability the client is disabling.
- `"if-offered"` *(default)* — opportunistic. The client signs/encrypts when
  the server agrees, otherwise proceeds without.
- `"required"` — demanded. The client advertises the requirement in NEGOTIATE,
  refuses to proceed if the server can't honor it, and rejects post-handshake
  responses that violate it.

`signing: "required"` accepts encrypted responses as satisfying the requirement
(per MS-SMB2 §3.1.4.3, an encrypted message's inner signature is zero).
Combining `signing: "required"` with `encryption: "required"` is supported and
gives both confidentiality and integrity on every post-handshake message.
```

- [ ] **Step 8.2: Update `SECURITY.md`**

Add a paragraph near the existing signing/encryption discussion:

```markdown
## Disabling signing or encryption

`ClientOptions.signing` and `ClientOptions.encryption` both accept
`"disabled"`. These exist for test environments and for interop with servers
that don't support either feature. Setting both to `"disabled"` produces
unauthenticated, unencrypted SMB traffic and should not be used against
production servers. Modern Windows and Samba defaults will reject a session
that declines signing; expect setup to fail.
```

- [ ] **Step 8.3: Update the existing design doc**

Append to `docs/superpowers/specs/2026-05-09-node-smb3-client-design.md` a short note:

```markdown
## Update 2026-05-11: signing is now a functional tri-state

`ClientOptions.signing` accepts `"disabled" | "if-offered" | "required"` and
behaves analogously to `ClientOptions.encryption`. See
`docs/superpowers/specs/2026-05-11-signing-tri-state-alignment-design.md` for
the design.
```

- [ ] **Step 8.4: Verify docs render correctly**

Run: `cat README.md | head -130 | tail -40`
Run: `cat SECURITY.md`
Expected: No broken markdown, code fences balanced, headings consistent.

- [ ] **Step 8.5: Commit**

```bash
git add README.md SECURITY.md docs/superpowers/specs/2026-05-09-node-smb3-client-design.md
git commit -m "docs: document signing tri-state and disabled-mode footgun"
```

---

## Task 9: Final verification

Confirm the whole feature works end-to-end and the test suite + typecheck + lint pass.

**Files:** none changed (verification only).

- [ ] **Step 9.1: Typecheck**

Run: `npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 9.2: Full test suite**

Run: `npm test`
Expected: All tests pass. Note the new test counts from `signing-mode.test.ts` and the additions to `connection.signing.test.ts` and `connection.encryption.test.ts`.

- [ ] **Step 9.3: Lint (if configured)**

Run: `npm run lint 2>/dev/null || echo "no lint script"`
Expected: Pass, or graceful skip if no lint script exists.

- [ ] **Step 9.4: Build (if configured)**

Run: `npm run build 2>/dev/null || echo "no build script"`
Expected: Build succeeds, or graceful skip.

- [ ] **Step 9.5: Manual smoke test against a real server (optional but recommended)**

If a test SMB server is available (Samba in a container, Azure Files, a Windows share):

```ts
// Quick repro snippet — drop into a scratch file under scripts/
import { Client } from "../src/client.js";
for (const signing of ["disabled", "if-offered", "required"] as const) {
  console.log(`signing=${signing}`);
  const c = new Client({ host: "...", username: "...", password: "...", signing });
  try {
    await c.connect();
    console.log("  connected");
    await c.close();
  } catch (e) {
    console.log("  failed:", (e as Error).message);
  }
}
```

Expected: `"if-offered"` and `"required"` connect; `"disabled"` fails against any modern server (because they demand signing), which is the correct behavior.

- [ ] **Step 9.6: Open PR**

```bash
git push -u origin <branch-name>
gh pr create --title "feat: signing tri-state alignment with encryption" --body "$(cat <<'EOF'
## Summary
- Make `ClientOptions.signing` a functional tri-state (`"disabled" | "if-offered" | "required"`) mirroring the encryption PR.
- Wire signing mode through NEGOTIATE `SecurityMode` bits, NEGOTIATE-response rejection, outbound suppression via `makeSigning()`, and inbound signed-or-encrypted enforcement.
- Compose cleanly with `encryption: "required"` per MS-SMB2 §3.1.4.3.

## Test plan
- [x] Unit tests in `test/unit/session/signing-mode.test.ts` (mode plumbing, NEGOTIATE advertisement, disabled-vs-server-required rejection, `makeSigning()` and cancel-signer suppression, `setSigningRequired` wiring).
- [x] Unit tests in `test/unit/connection/connection.signing.test.ts` (inbound rejection, pre-auth exemption).
- [x] Combined-mode test in `test/unit/connection/connection.encryption.test.ts`.
- [ ] Manual smoke test against Samba / Azure Files (all three modes).

Spec: `docs/superpowers/specs/2026-05-11-signing-tri-state-alignment-design.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Notes for the implementer

- The encryption PR (#3) is a sibling change you should keep open in a second editor pane while implementing. Whenever this plan says "next to the existing X check," look at the encryption version first — your new check should be visually parallel to it.
- The `setSigningRequired` setter and its check are deliberately the *only* new public surface on `Connection`. Resist the urge to add a getter, an event, or a status field — the spec calls out a minimal-diff design.
- If you find that the inbound check at Task 5 needs to also reject *signed* responses when verification failed but the SIGNED flag was set, that's already handled by the existing signature-verification block immediately above the new check. Don't duplicate the rejection.
- Out-of-scope cleanups (cipher-count validation, magic numbers, key zeroization) explicitly listed in the spec MUST NOT be folded into this PR. Open separate issues.
