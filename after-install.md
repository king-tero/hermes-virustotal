# Hermes VirusTotal Installed

Restart Hermes gateway processes so the plugin is loaded:

```bash
hermes gateway restart
```

Verify installation:

```bash
hermes plugins list
```

The plugin registers `vt_check_hash`, `vt_check_file`, a `pre_tool_call`
observer, and a `pre_llm_call` advisor hook.

Binary auto-upload to VTAI is on by default so the community can analyze
potential new malware. Scripts, source, and other text are never
auto-uploaded; archives are opt-in. See README for the full upload policy.

Optional settings:

```bash
VTAI_AUTO_UPLOAD_BINARIES=0      # disable default binary upload
VTAI_AUTO_UPLOAD_ARCHIVES=1      # enable archive upload (zip, 7z, rar, gz, bz2, xz)
VTAI_UPLOAD_NEVER_PATHS=**/*.env.local,**/vendor/**
VTAI_ENFORCE_KNOWN_MALICIOUS=1
VTAI_HASH_HOT_TIMEOUT=3
VTAI_HASH_MANUAL_TIMEOUT=8
VTAI_CONTEXT_TTL_SECONDS=1800
VTAI_MALICIOUS_CONTEXT_TTL_SECONDS=5400
VTAI_CONTEXT_DEDUP_MAX_SESSIONS=1024
```
