# Password Manager — Checkpoint 2

Local C++17 CLI using libsodium. All entry fields are encrypted on disk.
Passwords are entered without echo and are never printed.

## Build

macOS: install Apple command-line tools if missing (`xcode-select --install`).
With Homebrew installed:

```sh
brew install libsodium pkg-config
make
```

Ubuntu/Debian:

```sh
sudo apt update
sudo apt install build-essential pkg-config libsodium-dev python3
make
```

Run from the repository directory in an interactive terminal. The build creates
`pm`, the executable. It is excluded from Git.

## Commands

```sh
./pm --help
./pm init personal.vault
./pm add personal.vault
./pm list personal.vault
./pm update personal.vault
./pm delete personal.vault
```

init asks for a new master password (at least 12 bytes) and confirmation.
Other commands require that same password. add asks for a unique service,
username and password. update replaces the username and password of a service.
delete removes the service immediately. list shows service and username with
[hidden] instead of a password. Service names are case-sensitive.

Keep the vault in a directory owned and controlled by you. Back up the encrypted
file: there is no password recovery or undo. Do not delete the .lock file during
use. Use the same vault path for all commands.

## Code

All application code is in main.cpp:
- readPassword / readTextField: bounded input.
- readVaultFile: file checks and reading.
- unlockVault: authenticated decryption and entry parsing.
- saveVault: serialization, encryption and atomic save.
- main: command coordination.

Makefile contains the build recipe; test_cli.py contains integration tests.
Argon2id derives a key with 3 operations and 256 MiB of memory.
XChaCha20-Poly1305 encrypts all fields and authenticates the header.
Each save generates a fresh nonce. The binary payload uses length-prefixed fields,
without a JSON dependency. Wrong passwords or authentication failures do not
modify the vault. Saves use an encrypted temporary file and atomic replacement.
Limits: 1 MiB vault, 1000 entries, 256-byte text fields, 4096-byte passwords.

Sensitive buffers are cleared where practical. This does not guarantee erasure
of all OS/library copies or protect against a compromised OS. Power-loss
durability, rollback detection and recovery are not implemented. If interrupted
during hidden input and terminal echo remains disabled, run `stty echo`.

Unlike the original planned get command, Checkpoint 2 never displays passwords.
There is no clipboard/export feature. Make replaces the originally proposed CMake.

## Tests

```sh
python3 test_cli.py
```

Tests use disposable temporary vaults and a pseudo-terminal. They cover persistence,
hidden output, wrong passwords, overwrite refusal, updates, deletion, tampering,
truncation and permissions. Tested on macOS; Linux instructions are not verified here.

## AI assistance

OpenAI Codex assisted with implementation, refactoring and tests.