# Secure Programming

Repository for course labs and final project

## Project: Password Manager

A local command-line password manager written in C++17.
The application will store credentials in an encrypted vault file.
The user will unlock the vault using a master password.

### Planned features

- Create a vault protected by a master password.
- Add credentials containing a service name, username, and password.
- List saved entries without displaying passwords.
- Retrieve a selected entry, including its password.
- Update and delete entries.
- Encrypt and authenticate the vault using libsodium.

### Scope and limitations

The first version will support one local vault per invocation.
It will not include cloud synchronisation, a browser extension,
a graphical interface, or shared access between users.

The application will not intentionally write the master password,
encryption key, or decrypted credentials to disk.
Sensitive data will be kept in memory only as long as required.
Operating-system swap and memory-dump limitations are discussed
in the design document.

### Project status

Checkpoint 1: architecture and threat modelling.
The application is not implemented yet.

### Technology choices

- **C++17:** provides standard containers and RAII for organising
  the application and managing resources.
- **libsodium:** provides password-based key derivation,
  authenticated encryption, secure randomness, and memory-clearing
  functions. Cryptographic algorithms will not be implemented manually.
- **nlohmann/json:** provides JSON parsing and serialisation for
  the encrypted payload. Parsed data will still require validation.
- **CMake:** manages compilation and library dependencies.

The initial target platform is macOS.

### Planned command-line interface

The executable will be named `password_manager`.

| Command | Purpose |
| --- | --- |
| `password_manager init <vault>` | Create a new vault and confirm the master password; refuse to overwrite an existing file |
| `password_manager add <vault>` | Prompt for a service, username, and password; assign an entry ID |
| `password_manager list <vault>` | List entry IDs, services, and usernames without displaying passwords |
| `password_manager get <vault> <id>` | Display one entry, including its password |
| `password_manager update <vault> <id>` | Prompt for changes to an existing entry |
| `password_manager delete <vault> <id>` | Delete an entry after confirmation |
| `password_manager --help` | Display usage information |

Commands accessing an existing vault will request the master password
through a hidden interactive prompt. New entry passwords will also
use hidden input. Passwords will not be accepted as command-line arguments.

Each invocation will perform one operation and exit, clearing sensitive
buffers where possible. There will be no persistent unlocked session.

### Build and run plan

At Checkpoint 1, the repository contains design documentation.
The application and build configuration are not implemented yet.
The commands below describe the intended workflow and cannot yet
build or run this project.

Prerequisites:

- A C++17 compiler, such as Apple Clang from Xcode Command Line Tools.
- Homebrew for installing the planned dependencies.

Install dependencies on macOS:

```bash
brew install cmake pkgconf libsodium nlohmann-json
```

After source files and `CMakeLists.txt` have been implemented,
run these commands from the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The planned executable location is `build/password_manager`.

Example usage after implementation:

```bash
./build/password_manager init demo.vault
./build/password_manager add demo.vault
./build/password_manager list demo.vault
./build/password_manager get demo.vault 1
```

The final command assumes that an entry with ID 1 exists.

### Design document

See [design.md](design.md) for the architecture, threat model,
vault format, and cryptographic scheme.
