# Password Manager - Checkpoint 3 Report Draft

Date: 20 November 2026  
Repository: https://github.com/eZlanek/ICS0022-MB  
Baseline inspected: `77745d8` (Checkpoint 2)

## 1. Introduction

This project is a local terminal-based password manager written in C++17 using
libsodium. A vault contains service names, usernames and passwords. The supported
operations are creation, addition, listing, updating and deletion. A master
password is required to unlock an existing vault. There is no network service,
cloud storage, separate application-account database or graphical interface.

Checkpoint 3 strengthens the working Checkpoint 2 implementation with secure
memory ownership, stricter validation, structured logging, OS-user access checks
and interruption handling. The supplied Password Manager rubric is the target;
File Manager requirements about deleting arbitrary external files are not part
of this application. The existing no-password-display interface is retained.
This is feature-complete for that supported CLI scope, not a general-purpose
password manager with password retrieval, clipboard integration or recovery.

## 2. Implementation

### 2.1 Structure and data flow

`main.cpp` contains the application. `readInput` manages terminal input,
`SecureBuffer` owns secret memory, `Storage` handles files and ownership, `Audit`
records fixed-format events, and the vault functions derive keys and parse records.

The program validates the command and path, obtains an exclusive vault lock and
opens a protected audit log. For an existing vault it checks file ownership,
size and the fixed header before asking for a master password. Argon2id derives
the key. Successful authenticated decryption and payload validation are required
before record operations. Ownership is checked again before executing an operation
and before committing changes.

### 2.2 Cryptography and file format

The version-1 file format remains compatible with Checkpoint 2. Its 62-byte header
contains magic/version/algorithm bytes, two 64-bit little-endian KDF parameters,
a 16-byte salt and a 24-byte nonce. The remaining data is the encrypted payload
followed by a 16-byte authentication tag. The payload is a record count followed
by length-prefixed service, username and password fields, not JSON.

Argon2id derives a 32-byte key using 3 operations and 256 MiB of memory. Only those
stored KDF settings are accepted, preventing a modified header from requesting
unbounded work. XChaCha20-Poly1305 authenticates both the encrypted payload and
the public header. Each save uses a new random nonce. Keys and master passwords
are not deliberately written to disk. These choices follow the libsodium
password-hashing and AEAD documentation [1, 2].

### 2.3 Secure memory

Application-owned master passwords, keys, plaintext payloads and input fields use
`SecureBuffer`, a non-copyable RAII owner of a `sodium_malloc` allocation. Locking
is explicitly checked using `sodium_mlock`; failure aborts rather than silently
continuing with an unlocked application buffer. The entire allocation is zeroed
before `sodium_free`. Buffers have fixed capacities, and moves transfer ownership.

Parsed entries are non-owning views into the secure plaintext allocation. New
fields are read directly into secure input buffers. Serialisation uses another
secure buffer; ordinary byte vectors contain only public headers or ciphertext.
The master-password buffer is cleared after key derivation. Exception unwinding
clears buffers on invalid input, authentication failure, I/O failure and handled
signals. Core dumps are disabled. These measures follow libsodium's memory API,
whose documentation also describes the limits of locking and wiping [3].

### 2.4 Validation and access control

Commands are an allowlist. Text fields and passwords are bounded and checked for
valid UTF-8. Control characters, malformed encodings and invisible direction
controls are rejected rather than silently changing a secret. Service names are
unique and case-sensitive. Record counts, lengths, trailing payload data, file
size and KDF parameters are validated. Terminal output includes only validated
service/username fields; passwords always appear as `[hidden]`.

The application does not execute shell commands or use service names as file
paths. Shell metacharacters remain data. Vault paths reject parent traversal and
symlink components and are resolved with directory file descriptors and `openat`.
Files must be regular, mode 0600, singly linked and owned by the real UID. The final
directory must be owned by that user and not writable by others. UID/GID privilege
mismatches are rejected. File identity and access are rechecked before commit.

Per-user access means an OS-user boundary: every record inherits its vault's owner.
There are no per-record owners, shared vault permissions or separate usernames for
logging in. This interpretation matches the original single-user local design.
It does not isolate mutually hostile processes sharing the same UID or protect
against a privileged administrator.

### 2.5 Structured logging and error handling

A protected `<vault>.audit.jsonl` file records timestamp, UID, PID, allowlisted
command, event and outcome. Logged events cover operation start/end,
authentication success/failure, save attempts and interruption. All text values
come from fixed literals, never record data or raw exception messages. No master
password, entry password, key, service, username or vault path is logged.

An operation cannot proceed if the log cannot be safely opened. Unsafe paths and
lock/log-open failures produce a generic error without creating a fallback log in
an untrusted location. A failure after a committed write is reported as possibly
completed, so the user can inspect the vault before retrying. Logs are local audit
records, not tamper-evident evidence. Log rotation is not yet implemented.

### 2.6 Ctrl+C and saving

Handlers for SIGINT, SIGTERM, SIGHUP and SIGPIPE only set a `sig_atomic_t` flag.
The main execution path notices cancellation and unwinds normal C++ resource
owners. It does not allocate, log, erase memory or throw inside a signal handler.
Terminal input settings are restored, secure buffers are wiped, temporary files
are removed and file descriptors release the exclusive lock.

Cancellation is checked around terminal reads, parsing and I/O. Argon2id cannot
be safely unwound from the signal handler, so cancellation waits for that library
call to return. SIGINT produces exit status 130.

Updates are encrypted into an exclusive temporary file in the same directory.
After a successful flush and access recheck, rename atomically replaces the old
vault. Creation uses an exclusive hard-link commit to avoid overwriting an
existing file, then removes the temporary name. The directory is synced.
Before commit, cancellation preserves the previous vault. After commit, the
complete new vault remains; the interruption message explicitly reports this.

## 3. Security Analysis

### 3.1 Threats and remaining risks

| Threat | Implemented measure | Remaining limitation |
| --- | --- | --- |
| Offline guessing after copying a vault | Argon2id and a strong master password | Weak passwords remain guessable; no online attempt limit can prevent offline attacks |
| Modified ciphertext/header | AEAD verification before record access | Deletion or replacement with an older valid vault is not detected |
| Secrets left in process memory | Guarded/locked buffers, prompt cleanup, no secret string copies, disabled core dumps | Registers, kernel/library copies, swap/hibernation and privileged inspection are not fully controlled |
| Access by another OS user | UID/mode/type/link checks on files and an authenticated vault for every record operation | No protection from the same UID, root, or a copied vault's offline attack |
| Malformed fields or file structure | Byte/count limits, UTF-8 and payload validation, fixed KDF parameters | Sanitizer/fuzz tests are bounded, not a proof of absence of parser defects |
| Command or terminal injection | No shell invocation; controls rejected before display | The user can intentionally disclose displayed service/username metadata |
| Broken save or Ctrl+C | Encrypted temp file, atomic commit and RAII cleanup | SIGKILL, OS crashes, full-device faults and power loss can bypass cleanup |
| Secrets or internals in logs/errors | Fixed-schema log literals and generic errors | Audit timing/UID/command metadata is visible to the log owner; logs can be edited by that owner |

Deleting a record rewrites the encrypted active vault without that record and
clears application buffers. It does not promise physical deletion from SSDs,
snapshots, backups or a previously copied encrypted file. This distinction is
necessary even though the current rubric is for Password Manager, not File Manager.

### 3.2 Verification

`make test` runs C++ unit/security checks plus a Python pseudo-terminal suite.
The unit checks cover zero-before-free, ownership transfer, exception cleanup,
locking failure, access policy, exact cryptographic round trips, malformed records
and 2000 randomly generated malformed payloads. The integration suite covers CLI
operations, invalid inputs, wrong passwords for every record command, file/link
policies, generic errors, log confidentiality and cancellation.

Real terminal Ctrl+C bytes are tested during every input stage. Deterministic
pause points in a separately compiled test binary exercise cancellation before
and after commit and permit access changes during an operation. Fault injection
covers failures before and after commit. The production binary contains no such
environment-variable hooks. Tests compare original file bytes, check that no
temporary files remain, inspect complete terminal settings, and reopen vaults to
prove the lock was released and the contents remain usable.

The suite is repeated with AddressSanitizer and UndefinedBehaviorSanitizer.
A separate compatibility check uses the baseline executable to create a synthetic
vault, reads and updates it with Checkpoint 3, then reads it with Checkpoint 2.
No personal vault or credentials are used. Actual results and environment are
recorded in [TEST_RESULTS.md](TEST_RESULTS.md).

Foreign-UID policy is tested with synthetic `stat` metadata. End-to-end tests use
the current OS account, not a newly created second account. Libraries supplied by
the system/package manager are not themselves rebuilt with sanitizers. Neither
method establishes physical erasure or complete resistance to privileged malware.

### 3.3 Requirement mapping

| Password Manager Checkpoint 3 requirement | Evidence |
| --- | --- |
| Secure memory handling | `SecureBuffer`, `Vault` views, input guards; unit wipe/exception/move/lock tests |
| Full input validation and sanitisation | `validText`, path resolution, `validateHeader`, `parseEntries`; boundary and malformed-input tests |
| Structured logging and secure errors | `Audit`, fixed event values, generic outer error handling; JSON/log-secret checks |
| Per-user control on every record operation | `Storage::authorize`, OS ownership and successful vault authentication; permission-change and wrong-password tests |
| Passing input and memory tests | `make test`, `make sanitize`, recorded results |
| Draft report | Introduction, Implementation, Security Analysis and Conclusion in this file |

## 4. Conclusion

The Checkpoint 3 implementation completes the supported local CLI scope while
adding explicit memory ownership, stronger validation, structured events and
access checks. Tests demonstrate orderly cancellation with terminal restoration
and an intact old-or-new vault around the commit boundary. The format remains
compatible with valid Checkpoint 2 vaults.

The work remains an educational implementation. The stated scope excludes
password display, shared-account permissions, recovery, cloud synchronisation,
rollback protection and physical deletion guarantees. Future work would include
independent review, Linux verification, log rotation and a separate-OS-account
integration test. The report and AI assistance declaration should be reviewed
before submission under the course's applicable rules.

## References

1. [libsodium: password-based key derivation](https://doc.libsodium.org/password_hashing/default_phf)
2. [libsodium: XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
3. [libsodium: secure memory](https://doc.libsodium.org/memory_management)

## AI assistance

OpenAI Codex inspected the existing repository and assisted with the implementation,
test suite, debugging, documentation and this report draft. Checks were executed
on the local macOS environment using synthetic data. Documentation references were
consulted by the assistant; this declaration does not claim independent student
verification that has not been performed.
