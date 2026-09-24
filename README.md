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

The master password and encryption key will not be stored on disk.
Decrypted credentials will only be used in memory while the vault
is unlocked.

### Project status

Checkpoint 1: architecture and threat modelling.
The application is not implemented yet.
