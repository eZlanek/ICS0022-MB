# Password Manager - Checkpoint 3

A local C++17/libsodium terminal application. All vault fields are encrypted on
disk. The supported commands remain `init`, `add`, `list`, `update` and `delete`.
Passwords are never printed, exported or accepted as command-line arguments.

## Build and run

macOS, with Apple Command Line Tools and Homebrew available:

```sh
brew install libsodium pkg-config
make
./pm --help
```

Ubuntu/Debian build prerequisites (not tested on Linux in this checkpoint):

```sh
sudo apt install build-essential pkg-config libsodium-dev python3
make
```

Keep the vault in a directory owned by your OS user and not writable by other
users. The following creates a separate private directory, not a new account:

```sh
mkdir -m 700 vault-data
./pm init vault-data/personal.vault
./pm add vault-data/personal.vault
./pm list vault-data/personal.vault
./pm update vault-data/personal.vault
./pm delete vault-data/personal.vault
```

`init` requires a master password of at least 12 bytes and confirmation; it never
overwrites an existing vault. All other commands authenticate the master password.
`add` requires a unique service name. `update` replaces its username and password.
`delete` removes the named service immediately. `list` displays service and
username with `[hidden]` instead of the password. Service matching is case-sensitive.

All prompts, including service and username, use hidden input to keep partial
fields out of the terminal. Type normally and press Enter; Backspace is supported.
There is no password recovery. Back up the encrypted vault before using it.

## Validation and access policy

- Maximum 1000 records and 1 MiB encrypted vault.
- Service and username: 1-256 bytes of valid UTF-8; no control characters,
  direction overrides, `|`, or leading/trailing ASCII spaces.
- Passwords: 1-4096 bytes of valid UTF-8; no control characters or direction
  overrides. Existing nonempty master passwords remain accepted for unlocking.
- The existing version-1 binary format and Argon2id settings (3 operations,
  256 MiB) are preserved. JSON and CMake are not used.
- Vault paths: printable ASCII, no `..`, empty components, backslashes or symlink
  components; final filename at most 180 bytes and full path at most 3000 bytes.
  Use a physical path if a system alias such as `/tmp` or `/var` is a symlink.
- Vault, lock and audit log must be regular files, owned by the current real UID,
  with mode 0600 and one hard link. The vault directory must be owned by that UID
  and not group/world writable. Setuid/setgid execution is refused.
- Each record operation requires a successfully authenticated vault plus a fresh
  ownership check. All records inherit the owner of their vault. There are no
  separate application accounts or shared vaults.

A copied encrypted vault can still be attacked offline; owner checks do not
replace encryption or a strong master passphrase. Processes running as the same
OS user, privileged malware and administrators are outside the isolation boundary.

## Ctrl+C and safe saves

SIGINT (Ctrl+C), SIGTERM and SIGHUP request orderly shutdown. Password input is
restored, sensitive application buffers are wiped and file descriptors close,
releasing the lock. A running Argon2id call finishes before the program can
respond to cancellation; it is not forcibly terminated mid-library-call.

Before the atomic save commit, cancellation leaves the original vault unchanged
and removes the temporary file. After commit, the new complete vault remains and
the message states that changes were saved. SIGINT exits with status 130.

Saves write ciphertext to an exclusively created mode-0600 temporary file in the
same directory, flush it, recheck access, atomically commit, and sync the directory.
A failure after commit reports that the operation may have completed. If that
happens, inspect the vault before retrying. Do not remove `.lock` files during use.

SIGKILL, power loss and a failing OS cannot run application cleanup. No guarantee
is made of physical erasure from SSDs, snapshots, backups, swap or CPU registers.

## Secure memory and logs

Master passwords, keys, decrypted payloads and input fields use move-only guarded
libsodium allocations. Memory locking is checked; allocation/locking failure
aborts the operation. Buffers are explicitly zeroed before release, including
exception and cancellation paths. Core dumps are disabled. Parsed records are
views into the secure buffer, avoiding ordinary heap copies of secret fields.

Each vault has a `<vault>.audit.jsonl` log. Events contain only timestamp, UID, PID,
known command, event name and outcome. No passwords, keys, records, paths or raw
exception messages are logged. User-facing failures are generic. Invalid paths,
unsafe log files and lock failures are rejected before a log can safely be opened.
The local log is not tamper-proof and currently has no automatic rotation.

## Tests

```sh
make test
make sanitize
```

`make test` runs C++ memory/parser/crypto checks and a Python pseudo-terminal suite.
`make sanitize` repeats them with AddressSanitizer and UndefinedBehaviorSanitizer.
Only `pm-test` and `pm-sanitize` contain deterministic failure/pause hooks. The
production executable `pm` does not recognise the test environment variables.
All tests use synthetic credentials and disposable directories.

See [TEST_RESULTS.md](TEST_RESULTS.md) for measured results and limitations.
See [REPORT_DRAFT.md](REPORT_DRAFT.md) for the report and requirement mapping.
[design.md](design.md) is the earlier design; this README describes the actual CLI.

## AI assistance

OpenAI Codex assisted with the Checkpoint 3 implementation, tests, documentation
and report draft. Automated checks were executed on macOS; this does not establish
absence of all vulnerabilities or replace independent review.
