# Skill: VirusTotal Reputation Review Protocol

Use this protocol when VTAI/VirusTotal reports a malicious or suspicious file
hash.

## Procedure

1. Stop before executing the artifact.
2. Summarize the file path, hash, verdict, and detection stats.
3. Explain that this is a reputation signal for a known artifact, not a semantic
   analysis of intent.
4. Recommend a verified source, source-code review, sandbox execution, or human
   approval before proceeding.
5. If Hermes memory tools are available, record malicious hashes as hostile
   indicators for future sessions.

## Alert Template

> **VirusTotal reputation warning**
>
> Artifact: `[path]`
>
> SHA256: `[hash]`
>
> Verdict: `[malicious/suspicious/unknown]`
>
> Summary: `[short summary of VTAI/VirusTotal analysis]`
>
> Action: I will not treat this file as trusted without explicit review.
