# Checkpoint 3 - Verification Record

Run date: 20 November 2026. All data was synthetic. No personal vault was opened,
modified or decrypted.

## Environment

- macOS 27.2.1 (26B131), Apple Silicon arm64.
- Apple clang 21.0.0 (clang-2100.4.1.1).
- libsodium 1.0.22 from Homebrew.
- Python 3.14.8.
- Inspected local and GitHub baseline: `77745d8835ff30996ff4774baf5cff77c65c15ae`.

## Results

| Check | Actual result |
| --- | --- |
| Original Checkpoint 2 build and integration script | PASS before changes |
| `make test` | PASS: C++ security/unit checks and 29 Python integration tests; integration run 19.012 seconds |
| `make sanitize` | PASS: C++ checks and 28 Python tests, 1 intentional skip; integration run 19.515 seconds |
| ASan and UBSan diagnostics | No diagnostics in these runs |
| Clang static analyser | Exit 0, no diagnostics |
| `git diff --check` | PASS |
| Baseline vault compatibility | Old executable created vault, new executable read/updated it, old executable read updated result: PASS |

The sanitizer build intentionally enables test hooks. Therefore the check that
those hooks are absent from the production binary is skipped in that build.
That check passed against the ordinary `pm` executable. It is not a functional
security-test failure or an untested production hook.

## Memory and parser checks

- Secret allocations are non-copyable and transfer ownership on moves.
- An observer checks that all bytes are zero immediately before deallocation.
- Exception/cancellation unwinding invokes buffer cleanup.
- Simulated memory-lock failure fails closed.
- Policy checks reject foreign-UID metadata, extra hard links and unsafe modes.
- UTF-8 validation covers boundaries, invalid encodings, NUL, controls and bidi controls.
- Payload checks cover truncation, excessive counts/lengths, duplicate records and trailing data.
- 2000 random malformed decrypted payloads exercise parser bounds.
- An exact password round trip is checked inside the C++ test without printing it.
- Ciphertext and header tampering are rejected.
- Unauthenticated calls to the save layer are rejected.

## Ctrl+C and interruption checks

Tests use a controlling pseudo-terminal, send actual Ctrl+C bytes during hidden
input, and compare the complete terminal attributes after exit. The master side
is used for that comparison because macOS revokes the slave after session exit.

Covered input stages: master password, confirmation, service, username and entry
password. EOF is tested as well. SIGTERM cleanup is checked separately. A SIGINT
is also delivered during the configured Argon2id operation.

A separate test executable pauses at controlled boundaries. SIGINT is delivered
before KDF, after unlock, after temporary-file creation, before commit and after
commit. Before-commit cases preserve the original vault byte for byte. The
post-commit case contains the complete new record and reports that it was saved.
Tests verify no temporary files remain and reopen the vault after cancellation.

## Access, logs and saving

- Wrong passwords cannot access any of list/add/update/delete.
- Unsafe vault modes are denied for every record command.
- Symlink/hardlink/FIFO vaults, traversal, unsafe parents and lock/log substitution are rejected.
- Concurrent access fails safely and the lock is released after Ctrl+C.
- Permission changes after unlock and immediately before commit are rechecked.
- Failures before commit preserve the original file.
- A failure after commit leaves the new file usable and reports an uncertain completed operation.
- Logs parse as JSON with the expected fixed keys; master/entry passwords, service,
  username, wrong-password input and vault path are absent.
- Production binaries do not recognise the test-only environment variables.

## Scope of evidence

No cross-OS run, second-OS-account integration run, physical memory forensic test,
SSD erasure test, power-loss test or full-disk fault test was performed. Foreign-UID
policy is checked through synthetic metadata, while actual integration tests use
the current account and real file permissions. Fault injection is compiled only
into test executables. The externally installed libsodium library is not rebuilt
with sanitizers. Passing tests are evidence for these cases, not proof of complete
security or certification.

## Reproduction

```sh
make test
make sanitize
clang++ --analyze -std=c++17 $(pkg-config --cflags libsodium) main.cpp
```

The first two commands use disposable temporary directories. The third writes a
local analysis file, which is not part of the deliverables. The separate legacy
compatibility experiment compiled/used the baseline executable and did not require
any user's existing vault.
