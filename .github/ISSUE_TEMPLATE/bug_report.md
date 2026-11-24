---
name: Bug Report (.tape Replay)
about: Report a reproducible bug with an attached DTP v0.1 .tape session archive
title: "[bug]: "
labels: ["bug"]
---

## Summary

A concise description of what happened and what you expected to happen.

## Attach a Reproducible `.tape` Archive

If you can reproduce the issue locally, record it with DevTape and export a privacy-reviewed `diff-only` (or `trace-only`) `.tape` archive:

```bash
# 1. Record the failing command or session
devtape record --out bug.tape --db .devtape/sessions.db -- <your-failing-command>

# 2. List the recorded session ID
devtape sessions --db .devtape/sessions.db

# 3. Export with the diff-only privacy profile and review the redaction report
devtape export <SESSION_ID> \
  --db .devtape/sessions.db \
  --profile diff-only \
  --review \
  --out issue-repro.tape
```

- **Attached `.tape` file:** <!-- Drag and drop `issue-repro.tape` (or a `.zip` containing it) here -->
- **`devtape export --review` output:**
  ```json
  Paste the JSON review report printed to stderr here
  ```

## Environment

Run `devtape doctor` and paste the JSON output below:

```json
{
  "git": "...",
  "pty": "...",
  "term": "...",
  "shell": "...",
  "cwd_write": "ok",
  "scrubber": "dtp-scrub-0.1",
  "codec_roundtrip": "ok"
}
```

- **DevTape Version (`devtape --version`):**
- **OS & Architecture:**
- **Rust Toolchain (`rustc --version`):**

## Additional Context

Add any stack traces, `devtape inspect` snippets, or notes about your environment here.
