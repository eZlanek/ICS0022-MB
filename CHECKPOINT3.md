# Checkpoint 3 - Password Manager

## Deliverables

- Application: `main.cpp`, built as `pm` using `Makefile`.
- Tests: `tests/unit.cpp` and `test_cli.py`.
- Report: `REPORT_DRAFT.md`.
- Verification record: `TEST_RESULTS.md`.
- Usage and limits: `README.md`.

## Changes since Checkpoint 2

- Secure, non-copyable buffers for all application-owned secret fields.
- Checked memory locking, explicit wiping and cleanup during exceptions.
- Strict field/UTF-8, payload, path, owner and permission validation.
- Fixed-schema JSONL events without secret data or internal exception strings.
- Real-UID ownership plus authenticated access for every record operation.
- Ctrl+C handling, terminal restoration and old-or-new atomic save semantics.
- Negative tests, fault injection and ASan/UBSan runs.

The current supported command set and version-1 vault format are retained.
The previously planned `get` command is not introduced because the implemented
Checkpoint 2 interface never displays passwords in plaintext.

No personal vault was used for testing. The implementation and report were
prepared with OpenAI Codex assistance.
