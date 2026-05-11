# Contributing to smb3-client

Thanks for your interest. This is a small project; contributions are welcome
and triaged by one maintainer.

## Licensing of contributions

By submitting a pull request, issue comment, or any other contribution to this
repository, you agree that your contribution is licensed under the project's
[MIT License](./LICENSE) — the same terms under which the rest of the code is
distributed. You retain copyright on your contribution; you grant the project
and its users an MIT license to use it.

If you cannot make this representation (for example, your employer holds the
copyright and hasn't approved the contribution), please don't submit it.

## Reporting bugs

Open a GitHub issue. Please include:

- The version of `smb3-client` and Node.js you're running.
- The SMB server you're connecting to (Windows version, or Samba version).
- A minimal reproduction. A short `tsx` script that reproduces the bug is
  ideal. If the failure involves wire bytes, a Wireshark `.pcapng` clipped
  to the relevant frames is gold.
- The exact error and stack trace.

For **security vulnerabilities**, do **not** open a public issue. See
[SECURITY.md](./SECURITY.md) for the private reporting channel.

## Suggesting enhancements

Open an issue first to discuss the design before coding, especially for:

- New SMB2 features (leases, durable handles, multi-channel, Kerberos, DFS —
  see "Out of scope" in the design spec for the deliberate v1 omissions).
- Public API changes.
- Architectural refactors.

Small focused fixes don't need an issue first — just send the PR.

## Development setup

```bash
git clone <fork>
cd smb3-client
npm install
npm run verify     # typecheck + lint + 108 unit tests
npm run build      # produces dist/
```

To run integration tests against a real Windows server:

```bash
cp .env.example .env
$EDITOR .env       # fill in your server, credentials, share
set -a && . ./.env && set +a
npm run test:integration
```

## Pull request checklist

Before opening a PR, please confirm:

- [ ] `npm run verify` passes (typecheck, lint, all unit tests).
- [ ] New behavior has a unit test added under `test/unit/`. Follow TDD:
      write the failing test first.
- [ ] If the change affects wire-level behavior, add a unit test against a
      captured or synthetic SMB2 frame in `test/unit/wire/`.
- [ ] If you have access to a Windows server, run `npm run test:integration`
      and mention which scenarios you exercised. CI does not run integration
      tests.
- [ ] Public API changes are reflected in `README.md` and types in
      `src/types.ts`.
- [ ] Commit messages follow Conventional Commits style: `feat:`, `fix:`,
      `test:`, `docs:`, `refactor:`, `chore:`. Scopes are layer names —
      `feat(connection): …`, `fix(open): …`, etc.
- [ ] One logical change per PR. Don't bundle unrelated fixes; they're harder
      to review and revert.

## Coding conventions

- **TypeScript strict mode** is non-negotiable. The project enables
  `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`. New code must
  type-check without `any`. Use `unknown` and narrow.
- **Layered architecture.** Code lives in `src/{transport,wire,connection,session,tree,open,rpc,client}`.
  A layer must only depend on the layer directly below it. Don't reach
  through layers.
- **No new runtime dependencies** without discussion. Node `node:*` modules
  are fine.
- **Endianness.** All SMB2 fields are little-endian. The single exception is
  the 4-byte NBSS-style framer length, which is big-endian. The `Reader` /
  `Writer` helpers in `src/wire/buffer.ts` handle this — use them, don't
  reach for `Buffer.readUInt32LE` directly.
- **String encoding.** SMB2 paths and filenames are UTF-16LE without a null
  terminator. NDR strings (used by DCE/RPC) are UTF-16LE *with* null
  terminator. The `ndrUtf16` helper in `src/rpc/srvsvc.ts` knows the
  difference.
- **Conditional optional spreads.** Because of `exactOptionalPropertyTypes`,
  passing `undefined` to an optional field is a type error. Use:
  ```ts
  send(cmd, body, {
    sessionId,
    ...(signing !== undefined ? { signing } : {}),
  });
  ```
  rather than `signing: signing` when the value can be undefined.
- **No new comments** describing *what* the code does — names should already
  do that. Comments are for the *why*: subtle invariants, spec quirks, or
  workarounds for specific bugs. The existing codebase tries to follow this.

## Testing conventions

- Unit tests live in `test/unit/` mirroring the `src/` layout.
- Integration tests live in `test/integration/`, gated on `SMB_TEST_*`
  environment variables.
- **Pure codec functions** in `src/wire/structs/*` are unit-tested by
  encoding a typed object and asserting against captured/synthetic bytes,
  then decoding bytes back to a typed object. Round-trip property:
  `decode(encode(x))` deep-equals `x` where appropriate.
- **State machines** like `Connection.send` and `Session.setup` are tested
  with the `FakeTransport` helper in `test/helpers/fakeTransport.ts`. It
  scripts request/response pairs without a real socket.
- **Crypto** is unit-tested with known-answer vectors from the relevant RFCs
  or specs. New crypto code requires the same.

## Architectural decisions

The shape of the code is in
[`docs/superpowers/specs/2026-05-09-node-smb3-client-design.md`](./docs/superpowers/specs/2026-05-09-node-smb3-client-design.md).
If you want to deviate from it, open an issue to discuss before sending the
PR — substantive design changes are a heavier review than feature additions.

## Code review

The maintainer will review and either merge, request changes, or explain why
the change isn't a fit. Pre-1.0 the API can move; once a feature lands it is
not covered by a stability promise until 1.0.

## Conduct

Be civil. Reviews are about the code, not the contributor. There's no formal
code of conduct yet because the contributor base is small; if that changes,
one will be added.
