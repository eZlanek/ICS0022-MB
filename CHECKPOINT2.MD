# Checkpoint 2 — Password Manager

## Implemented
- Local encrypted vault storage using libsodium
- Argon2id master-password key derivation
- XChaCha20-Poly1305 authenticated encryption
- Master-password verification before accessing entries
- Commands: init, add, list, update, delete
- Hidden password input; stored passwords are never printed
- Input validation and atomic saving of encrypted data

## Verification
Built and tested on macOS.
Automated tests passed for creation, persistence, updates,
deletion, incorrect passwords, overwrite prevention,
tampered and truncated files, and file permissions.

## Build and run
See README.md for dependencies, build instructions and commands
Linux instructions have not yet been tested

## Limitations and next steps
- No password retrieval or clipboard functionality yet
- No master-password recovery
- Further error-handling and security testing before Checkpoint 3

## AI assistance
OpenAI Codex assisted with implementation, refactoring and tests