#include <algorithm>
#include <array>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

using Bytes = std::vector<unsigned char>;
// Version 1: magic + version + KDF + CPU limit + memory limit + salt + nonce.
constexpr size_t LIMIT = 1024 * 1024;
constexpr size_t HEADER = 62;
constexpr size_t SALT_OFFSET = 22;
constexpr size_t NONCE_OFFSET = 38;
constexpr uint64_t KDF_OPS = 3;
constexpr uint64_t KDF_MEMORY = 256 * 1024 * 1024;

// Input and small resource guards. Secret input never goes into command arguments.
void require(bool ok, const char *message) {
    if (!ok)
        throw std::runtime_error(message);
}
struct Secret {
    Secret() = default;
    Secret(const Secret &) = delete;
    Secret &operator=(const Secret &) = delete;
    std::array<unsigned char, 4096> b{};
    size_t n = 0;
    ~Secret() {
        sodium_memzero(b.data(), b.size());
    }
};
void readPassword(const char *prompt, Secret &s) {
    termios old{};
    require(isatty(STDIN_FILENO) && tcgetattr(0, &old) == 0,
            "Password input requires a terminal.");
    termios hidden = old;
    hidden.c_lflag &= ~ECHO;
    require(tcsetattr(0, TCSAFLUSH, &hidden) == 0, "Cannot hide input.");
    std::cout << prompt << std::flush;
    bool overflow = false;
    char c;
    ssize_t received;
    while ((received = read(0, &c, 1)) == 1 && c != '\n') {
        if (s.n < s.b.size())
            s.b[s.n++] = static_cast<unsigned char>(c);
        else
            overflow = true;
    }
    int restored = tcsetattr(0, TCSAFLUSH, &old);
    std::cout << '\n';
    require(restored == 0, "Cannot restore terminal input.");
    require(received == 1, "Password input ended.");
    require(!overflow && s.n > 0, "Password must contain 1..4096 bytes.");
}
std::string readTextField(const char *prompt) {
    std::cout << prompt << std::flush;
    std::string s;
    char c;
    while (std::cin.get(c) && c != '\n') {
        require(s.size() < 256, "Field exceeds 256 bytes.");
        s.push_back(c);
    }
    require(bool(std::cin), "Input ended.");
    require(!s.empty() && s.size() <= 256, "Field must contain 1..256 bytes.");
    require(std::all_of(s.begin(), s.end(),
                        [](unsigned char c) { return c >= 32 && c != 127; }),
            "Control characters are not allowed.");
    return s;
}
// Length-prefixed binary fields avoid a separate JSON dependency.
void appendInteger(Bytes &b, uint64_t n, size_t count) {
    while (count--) {
        b.push_back(n & 255);
        n >>= 8;
    }
}
uint64_t readInteger(const Bytes &b, size_t &p, size_t count) {
    require(p <= b.size() && count <= b.size() - p, "Invalid vault format.");
    uint64_t n = 0;
    for (size_t i = 0; i < count; i++)
        n |= uint64_t(b[p++]) << (8 * i);
    return n;
}
struct Entry {
    std::string service, username;
    Bytes password;
};
struct Vault {
    Bytes plaintext;
    std::vector<Entry> entries;
    std::array<unsigned char, 32> key{};
    ~Vault() {
        sodium_memzero(key.data(), key.size());
        sodium_memzero(plaintext.data(), plaintext.size());
        for (auto &e : entries)
            sodium_memzero(e.password.data(), e.password.size());
    }
};
struct FileDescriptor {
    int n;
    explicit FileDescriptor(int f) : n(f) {}
    ~FileDescriptor() {
        if (n >= 0)
            close(n);
    }
};
Bytes readVaultFile(int fd) {
    struct stat st{};
    require(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid() &&
                !(st.st_mode & 077),
            "Vault must be an owner-only regular file (chmod 600).");
    require(st.st_size >= 78 && st.st_size <= long(LIMIT), "Invalid vault size.");
    Bytes b(st.st_size);
    size_t p = 0;
    while (p < b.size()) {
        ssize_t n = read(fd, b.data() + p, b.size() - p);
        require(n > 0, "Read failed.");
        p += n;
    }
    return b;
}
void saveVault(const std::string &path, Bytes &header, Vault &vault, bool create) {
    Bytes &payload = vault.plaintext;
    sodium_memzero(payload.data(), payload.size());
    payload.clear();
    size_t payload_size = 4;
    for (const auto &e : vault.entries)
        payload_size += 12 + e.service.size() + e.username.size() + e.password.size();
    require(payload_size + HEADER + 16 <= LIMIT, "Vault is full.");
    // Reserve before adding secrets, so growth cannot leave old plaintext copies.
    payload.reserve(payload_size);
    appendInteger(payload, vault.entries.size(), 4);
    for (const auto &e : vault.entries) {
        for (const auto *s : {&e.service, &e.username}) {
            appendInteger(payload, s->size(), 4);
            payload.insert(payload.end(), s->begin(), s->end());
        }
        appendInteger(payload, e.password.size(), 4);
        payload.insert(payload.end(), e.password.begin(), e.password.end());
    }
    require(payload.size() + HEADER + 16 <= LIMIT, "Vault is full.");
    randombytes_buf(header.data() + NONCE_OFFSET, 24);
    Bytes encryptedFile = header;
    encryptedFile.resize(HEADER + payload.size() + 16);
    unsigned long long encryptedLength;
    require(crypto_aead_xchacha20poly1305_ietf_encrypt(
                encryptedFile.data() + HEADER, &encryptedLength, payload.data(),
                payload.size(), header.data(), header.size(), nullptr,
                header.data() + NONCE_OFFSET, vault.key.data()) == 0,
            "Encryption failed.");
    std::string temporaryPath = path + ".tmp.XXXXXX";
    FileDescriptor fd(mkstemp(temporaryPath.data()));
    require(fd.n >= 0, "Cannot create temporary file.");
    try {
        size_t writtenBytes = 0;
        while (writtenBytes < encryptedFile.size()) {
            ssize_t n = write(fd.n, encryptedFile.data() + writtenBytes,
                              encryptedFile.size() - writtenBytes);
            require(n > 0, "Write failed.");
            writtenBytes += n;
        }
        require(fsync(fd.n) == 0, "Flush failed.");
        if (create)
            require(link(temporaryPath.c_str(), path.c_str()) == 0,
                    "Vault already exists or cannot be created.");
        else
            require(rename(temporaryPath.c_str(), path.c_str()) == 0,
                    "Cannot replace vault.");
    } catch (...) {
        unlink(temporaryPath.c_str());
        throw;
    }
    unlink(temporaryPath.c_str());
}
// Authentication must succeed before any entries can be used.
void unlockVault(Vault &vault, const Bytes &header) {
    unsigned long long plaintextLength = 0;
    require(crypto_aead_xchacha20poly1305_ietf_decrypt(
                vault.plaintext.data(), &plaintextLength, nullptr, vault.plaintext.data(),
                vault.plaintext.size(), header.data(), header.size(),
                header.data() + NONCE_OFFSET, vault.key.data()) == 0,
            "Unable to unlock vault: incorrect password or damaged file.");
    vault.plaintext.resize(plaintextLength);
    size_t cursor = 0;
    auto entryCount = readInteger(vault.plaintext, cursor, 4);
    require(entryCount <= 1000, "Too many entries.");
    for (size_t i = 0; i < entryCount; i++) {
        Entry record;
        for (auto *text : {&record.service, &record.username}) {
            auto fieldLength = readInteger(vault.plaintext, cursor, 4);
            require(fieldLength > 0 && fieldLength <= 256 &&
                        fieldLength <= vault.plaintext.size() - cursor,
                    "Invalid entry.");
            text->assign(reinterpret_cast<char *>(vault.plaintext.data() + cursor),
                         fieldLength);
            cursor += fieldLength;
            require(std::all_of(text->begin(), text->end(),
                                [](unsigned char c) { return c >= 32 && c != 127; }),
                    "Invalid entry text.");
        }
        auto fieldLength = readInteger(vault.plaintext, cursor, 4);
        require(fieldLength > 0 && fieldLength <= 4096 &&
                    fieldLength <= vault.plaintext.size() - cursor,
                "Invalid password field.");
        record.password.assign(vault.plaintext.begin() + cursor,
                               vault.plaintext.begin() + cursor + fieldLength);
        cursor += fieldLength;
        vault.entries.push_back(std::move(record));
    }
    require(cursor == vault.plaintext.size(), "Trailing vault data.");
}

int main(int argc, char **argv) {
    try {
        require(sodium_init() >= 0, "libsodium initialization failed.");
        rlimit lim{0, 0};
        require(setrlimit(RLIMIT_CORE, &lim) == 0, "Cannot disable core dumps.");
        umask(077);
        if (argc == 2 && std::string(argv[1]) == "--help") {
            std::cout << "Usage: ./pm <init|add|list|update|delete> <vault-file>\n";
            return 0;
        }
        if (argc != 3) {
            std::cout << "Usage: ./pm <init|add|list|update|delete> <vault-file>\n";
            return 1;
        }
        std::string command = argv[1], path = argv[2];
        require(command == "init" || command == "add" || command == "list" ||
                    command == "update" || command == "delete",
                "Unknown command.");
        require(!path.empty() && path.size() < 3000, "Invalid path.");
        FileDescriptor lock(
            open((path + ".lock").c_str(), O_CREAT | O_RDWR | O_NOFOLLOW, 0600));
        require(lock.n >= 0, "Cannot open vault lock.");
        struct stat lockInfo{};
        require(fstat(lock.n, &lockInfo) == 0 && S_ISREG(lockInfo.st_mode) &&
                    lockInfo.st_uid == getuid() && !(lockInfo.st_mode & 077),
                "Lock must be an owner-only regular file.");
        require(flock(lock.n, LOCK_EX | LOCK_NB) == 0,
                "Vault is busy or lock unavailable.");
        Vault vault;
        Bytes header;
        Secret master;
        readPassword("Master password: ", master);
        if (command == "init") {
            require(master.n >= 12,
                    "Use at least 12 characters for the master password.");
            Secret confirm;
            readPassword("Confirm master password: ", confirm);
            require(master.n == confirm.n &&
                        sodium_memcmp(master.b.data(), confirm.b.data(), master.n) == 0,
                    "Passwords do not match.");
            header = {'P', 'M', 'G', 'R', 1, 1};
            appendInteger(header, KDF_OPS, 8);
            appendInteger(header, KDF_MEMORY, 8);
            header.resize(HEADER);
            randombytes_buf(header.data() + SALT_OFFSET, 16);
        } else {
            FileDescriptor fd(open(path.c_str(), O_RDONLY | O_NOFOLLOW));
            require(fd.n >= 0, "Cannot open vault.");
            Bytes file = readVaultFile(fd.n);
            header.assign(file.begin(), file.begin() + HEADER);
            require(std::memcmp(header.data(), "PMGR\1\1", 6) == 0,
                    "Unsupported vault format.");
            vault.plaintext.assign(file.begin() + HEADER, file.end());
        }
        size_t offset = 6;
        auto operations = readInteger(header, offset, 8),
             memoryBytes = readInteger(header, offset, 8);
        require(operations == KDF_OPS && memoryBytes == KDF_MEMORY,
                "Unsupported KDF parameters.");
        require(crypto_pwhash(vault.key.data(), 32,
                              reinterpret_cast<char *>(master.b.data()), master.n,
                              header.data() + SALT_OFFSET, operations, memoryBytes,
                              crypto_pwhash_ALG_ARGON2ID13) == 0,
                "Key derivation failed (insufficient memory).");
        sodium_memzero(master.b.data(), master.b.size());
        if (command != "init") {
            unlockVault(vault, header);
        }
        if (command == "list") {
            std::cout << "Service | Username | Password\n";
            for (const auto &e : vault.entries)
                std::cout << e.service << " | " << e.username << " | [hidden]\n";
            std::cout << vault.entries.size() << " entries\n";
            return 0;
        }
        if (command != "init") {
            auto service = readTextField("Service: ");
            auto entry =
                std::find_if(vault.entries.begin(), vault.entries.end(),
                             [&](const Entry &e) { return e.service == service; });
            if (command == "add") {
                require(entry == vault.entries.end(), "Service already exists.");
                require(vault.entries.size() < 1000, "Vault is full.");
                vault.entries.push_back({service, "", {}});
                entry = vault.entries.end() - 1;
            } else
                require(entry != vault.entries.end(), "Service not found.");
            if (command == "delete") {
                sodium_memzero(entry->password.data(), entry->password.size());
                vault.entries.erase(entry);
            } else {
                entry->username = readTextField("Username: ");
                Secret pass;
                readPassword("Entry password: ", pass);
                sodium_memzero(entry->password.data(), entry->password.size());
                entry->password.assign(pass.b.begin(), pass.b.begin() + pass.n);
            }
        }
        saveVault(path, header, vault, command == "init");
        std::cout << "Saved successfully. Passwords remain hidden.\n";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
