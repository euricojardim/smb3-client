# client_example

Runnable example scripts for [node-smb3](../README.md). Each script is self-contained: it creates its own working directory on the share where needed and cleans up after itself.

## Prerequisites

- Node.js >= 20
- `tsx` (pulled in as a dev dependency via `npm install` at the project root)
- A Windows SMB server and credentials — same as the integration tests

## Environment variables

The examples read the same env vars as `npm run test:integration`:

| Variable | Required | Default | Description |
|---|---|---|---|
| `SMB_TEST_HOST` | yes | — | Server hostname or IP |
| `SMB_TEST_PORT` | no | `445` | TCP port |
| `SMB_TEST_DOMAIN` | no | `""` | NTLM domain (leave blank for local/workgroup accounts) |
| `SMB_TEST_USERNAME` | yes | — | Username |
| `SMB_TEST_PASSWORD` | yes | — | Password |
| `SMB_TEST_SHARE` | yes | — | Share name (e.g. `public`) |

Copy `.env.example` to `.env` at the project root and fill in your values.

## Running an example

From the project root:

```bash
set -a && . ./.env && set +a
npx tsx client_example/01-negotiate.ts
```

Or export the variables manually and then run `npx tsx client_example/<script>.ts`.

## Examples

| Script | What it demonstrates |
|---|---|
| `01-negotiate.ts` | Low-level TCP connect + SMB NEGOTIATE — prints dialect, server GUID, max sizes |
| `02-stat.ts` | `client.stat()` — creates a temp file, inspects metadata, cleans up |
| `03-read-file.ts` | `client.readFile()` — write known content, read back, assert equality |
| `04-write-and-read.ts` | `client.writeFile()` + `readFile()` — 64 KiB random round-trip with SHA-256 check |
| `05-list-directory.ts` | `client.readdir()` — both name list and `withFileTypes` Dirent form |
| `06-rename.ts` | `client.rename()` — rename within the same share, verify before/after |
| `07-mkdir-rmdir.ts` | `client.mkdir()` + `rmdir()` — create and remove a directory |
| `08-stream-large-file.ts` | `createWriteStream()` + `createReadStream()` — 4 MiB pipeline with throughput stats |
| `09-watch.ts` | `client.watch()` — CHANGE_NOTIFY async iterator with AbortController |
| `10-list-shares.ts` | `client.listShares()` — DCE/RPC NetrShareEnum, confirms configured share is present |
