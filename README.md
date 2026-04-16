# Hermes VirusTotal (v0.1.1)

**Hermes VirusTotal** is a Hermes Agent plugin that adds [VirusTotal](https://www.virustotal.com) AI (VTAI)
reputation signals for file and hash workflows. It provides reputation context
that the model and the user can use when deciding what to trust.

## Features

* **Manual reputation tools**:
  * `vt_check_hash(hash)`: check a MD5, SHA1, or SHA256 in VTAI/VirusTotal.
  * `vt_check_file(path)`: hash a file in the active Hermes execution
    environment and check that hash.
* **Advisor context**: observed artifacts are summarized via `pre_llm_call` as
  fenced, untrusted context for the model. Context is scoped to the active
  Hermes session, deduplicated between turns, and aged out when stale.
* **Provenance metadata**: content created by `write_file`, `patch`, and
  `execute_code` is hashed and recorded with its VTAI/VirusTotal verdict when
  available.
* **Privacy-respecting upload policy**: binaries (ELF, PE/MZ, Mach-O, WASM,
  Java class, DEX) are auto-submitted to VTAI by default so the community can
  analyze potential new malware. Scripts, source code, markdown, and other
  text are never auto-uploaded. Archives are opt-in. A path blocklist and a
  secret-pattern scan short-circuit uploads that could leak user data.
* **Optional enforcement**: set `VTAI_ENFORCE_KNOWN_MALICIOUS=1` to block only
  exact content hashes that VTAI/VirusTotal reports as malicious. This is off by
  default.

## Installation

```bash
hermes plugins install king-tero/hermes-virustotal
```

Restart the gateway if you use Hermes through a messaging platform:

```bash
hermes gateway restart
```

Plugin skills are explicit plugin skills:

```bash
hermes -s hermes-virustotal:sentinel
hermes -s hermes-virustotal:ir-protocol
```

## How It Works

1. The plugin registers `vt_check_hash`, `vt_check_file`, `pre_tool_call`, and
   `pre_llm_call`.
2. `pre_tool_call` observes new content from file/code-writing tools
   (`write_file`, `patch`, `execute_code`) and stores local metadata. VTAI
   registration happens only on the explicit `vt_check_file` tool path.
3. `pre_llm_call` injects a compact VirusTotal advisor context with recent
   artifact paths, hashes, verdicts, stats, and short insight text for the
   current `session_id`.
4. By default, tool execution proceeds even when VTAI is unavailable or returns
   no data. This fail-open behavior is intentional to avoid friction.
5. If `VTAI_ENFORCE_KNOWN_MALICIOUS=1` is set, only exact content hashes with a
   malicious verdict are blocked.

## Configuration

Environment variables:

* `VTAI_AGENT_TOKEN`: VTAI token returned by `/api/v3/agents/register`.
* `VTAI_AGENT_ID` and `VTAI_AGENT_HANDLE`: Optional metadata saved after
  automatic VTAI registration for support and debugging.
* `VIRUSTOTAL_API_KEY`: Optional standard VirusTotal API key. If set, it is used
  before `VTAI_AGENT_TOKEN`.
* `VTAI_AUTO_UPLOAD_BINARIES`: Auto-submit binary content (ELF, PE/MZ,
  Mach-O, WASM, Java class, DEX) written via `write_file`/`patch`/
  `execute_code` when the hash is unknown. Defaults to `1`. Set to `0` to
  disable.
* `VTAI_AUTO_UPLOAD_ARCHIVES=1`: Opt in to auto-submitting archive content
  (ZIP, 7z, RAR, gzip, bzip2, xz). Defaults to off because archives may
  contain source code.
* `VTAI_UPLOAD_NEVER_PATHS`: Comma-separated glob patterns added on top of
  the built-in blocklist. Paths matching any pattern are never uploaded.
  Built-in blocklist covers `.env*`, `*.key`, `*.pem`, `id_rsa*`,
  `id_ed25519*`, `.ssh/*`, `secrets/*`, `*secret*`, `*password*`,
  `*credential*`, `known_hosts`, and `authorized_keys`.
* `VTAI_ENFORCE_KNOWN_MALICIOUS=1`: Opt in to blocking exact malicious hashes.
* `VTAI_HASH_HOT_TIMEOUT`: Hash reputation timeout for passive `pre_tool_call`
  observations. Defaults to `3`.
* `VTAI_HASH_MANUAL_TIMEOUT`: Hash reputation timeout for explicit
  `vt_check_hash` and `vt_check_file` calls. Defaults to `8`.
* `VTAI_HASH_TIMEOUT`: Backwards-compatible fallback used when the specific hot
  or manual timeout is unset.
* `VTAI_CONTEXT_TTL_SECONDS`: How long non-malicious artifact observations stay
  eligible for advisor context. Defaults to `1800`.
* `VTAI_MALICIOUS_CONTEXT_TTL_SECONDS`: How long malicious observations stay
  eligible for advisor context. Defaults to `5400`.
* `VTAI_CONTEXT_DEDUP_MAX_SESSIONS`: Maximum in-process sessions tracked for
  advisor context deduplication. Defaults to `1024`.
* `VTAI_REGISTER_TIMEOUT` and `VTAI_UPLOAD_TIMEOUT`: Registration and upload
  request timeouts in seconds. Both default to `30`.

## Scope

This plugin provides known-file reputation. Use Hermes sandboxing, approvals,
and core policy for hard enforcement.

## License

This project is Open Source under the MIT license. Contributions from the
cybersecurity and AI community are welcome.
