#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <vector>

using Bytes = std::vector<unsigned char>; // Public headers and ciphertext only.
constexpr size_t LIMIT = 1024 * 1024;
constexpr size_t HEADER = 62, SALT_OFFSET = 22, NONCE_OFFSET = 38;
constexpr uint64_t KDF_OPS = 3, KDF_MEMORY = 256 * 1024 * 1024;
constexpr size_t MAX_ENTRIES = 1000;

// Signal handlers only set a flag. Cleanup happens by normal stack unwinding.
volatile sig_atomic_t stopSignal = 0;
void requestStop(int signal) { stopSignal = signal; }
struct Cancelled {};
struct Failure { const char *code; };
void require(bool ok, const char *code) { if (!ok) throw Failure{code}; }
void checkCancelled() { if (stopSignal) throw Cancelled{}; }
void installSignals() {
    struct sigaction action{};
    action.sa_handler = requestStop;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0; // Do not restart an interrupted read automatically.
    for (int signal : {SIGINT, SIGTERM, SIGHUP, SIGPIPE})
        require(sigaction(signal, &action, nullptr) == 0, "setup_failed");
}

#ifdef PM_TESTING
// Only the separate test binary has fault injection or pause points.
bool testLockFailure = false;
void (*testWipeObserver)(const unsigned char *, size_t) = nullptr;
void testPoint(const char *name) {
    const char *point = std::getenv("PM_TEST_PAUSE");
    if (point && std::strcmp(point, name) == 0) raise(SIGSTOP);
    const char *failure = std::getenv("PM_TEST_FAIL");
    if (failure && std::strcmp(failure, name) == 0) throw Failure{"io_failed"};
}
#else
void testPoint(const char *) {}
#endif

// All application-owned secret data lives here, never in std::string/vector.
// Move-only, fixed allocation: resizing cannot abandon unwiped old copies.
class SecureBuffer {
    unsigned char *bytes_ = nullptr;
    size_t size_ = 0;
public:
    explicit SecureBuffer(size_t size) : size_(size) {
        require(size > 0 && size <= LIMIT, "invalid_input");
        bytes_ = static_cast<unsigned char *>(sodium_malloc(size));
        require(bytes_ != nullptr, "memory_failed");
        bool lockFailed = sodium_mlock(bytes_, size) != 0;
#ifdef PM_TESTING
        lockFailed = lockFailed || testLockFailure;
#endif
        if (lockFailed) {
            sodium_free(bytes_);
            bytes_ = nullptr;
            throw Failure{"memory_failed"}; // Fail closed, not silently unlocked.
        }
        sodium_memzero(bytes_, size_);
    }
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;
    SecureBuffer(SecureBuffer &&other) noexcept { swap(other); }
    SecureBuffer &operator=(SecureBuffer &&other) noexcept {
        if (this != &other) { SecureBuffer old(std::move(other)); swap(old); }
        return *this;
    }
    void swap(SecureBuffer &other) noexcept {
        std::swap(bytes_, other.bytes_); std::swap(size_, other.size_);
    }
    unsigned char *data() { return bytes_; }
    const unsigned char *data() const { return bytes_; }
    size_t size() const { return size_; }
    void clear() noexcept {
        if (bytes_) {
            sodium_memzero(bytes_, size_);
#ifdef PM_TESTING
            if (testWipeObserver) testWipeObserver(bytes_, size_);
#endif
        }
    }
    ~SecureBuffer() { clear(); sodium_free(bytes_); }
};

struct Field { const unsigned char *data; size_t size; };
bool equal(Field a, Field b) {
    return a.size == b.size && std::memcmp(a.data, b.data, a.size) == 0;
}
// Reject invalid UTF-8, terminal controls and invisible direction overrides.
// Shell metacharacters are ordinary data: the application never runs a shell.
bool validText(Field field, size_t maximum, bool password = false) {
    if (!field.size || field.size > maximum) return false;
    if (!password && (field.data[0] == ' ' || field.data[field.size - 1] == ' '))
        return false;
    for (size_t i = 0; i < field.size;) {
        uint32_t cp = field.data[i++];
        size_t count = 0;
        uint32_t minimum = 0;
        if (cp >= 0xc2 && cp <= 0xdf) { cp &= 31; count = 1; minimum = 0x80; }
        else if (cp >= 0xe0 && cp <= 0xef) { cp &= 15; count = 2; minimum = 0x800; }
        else if (cp >= 0xf0 && cp <= 0xf4) { cp &= 7; count = 3; minimum = 0x10000; }
        else if (cp >= 0x80) return false;
        if (count > field.size - i) return false;
        while (count--) {
            unsigned char c = field.data[i++];
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 63);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ||
            cp < 32 || (cp >= 0x7f && cp <= 0x9f) ||
            (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) ||
            (cp >= 0x2060 && cp <= 0x206f) || cp == 0xfeff) return false;
        if (!password && cp == '|') return false;
    }
    return true;
}

struct Descriptor {
    int value = -1;
    explicit Descriptor(int fd = -1) : value(fd) {}
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
    Descriptor(Descriptor &&other) noexcept : value(std::exchange(other.value, -1)) {}
    Descriptor &operator=(Descriptor &&other) noexcept {
        if (this != &other) { if (value >= 0) close(value); value = std::exchange(other.value, -1); }
        return *this;
    }
    ~Descriptor() { if (value >= 0) close(value); }
};

class TerminalMode {
    termios original_{};
    bool active_ = false;
public:
    TerminalMode() {
        require(isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original_) == 0,
                "input_failed");
        termios hidden = original_;
        hidden.c_lflag &= ~(ECHO | ECHONL | ICANON);
        hidden.c_cc[VMIN] = 1; hidden.c_cc[VTIME] = 0;
        require(tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0, "input_failed");
        active_ = true;
    }
    void restore() {
        if (!active_) return;
        int result;
        do { result = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_); }
        while (result < 0 && errno == EINTR);
        if (result == 0) active_ = false;
        require(result == 0, "input_failed");
    }
    ~TerminalMode() {
        if (active_) { try { restore(); } catch (...) {} }
    }
};

struct Input {
    SecureBuffer bytes;
    size_t length = 0;
    explicit Input(size_t capacity) : bytes(capacity) {}
    Field field() const { return {bytes.data(), length}; }
};
void readInput(const char *prompt, Input &input, bool password = false) {
    checkCancelled();
    input.bytes.clear(); input.length = 0;
    TerminalMode terminal;
    std::cout << prompt << std::flush;
    SecureBuffer character(1);
    while (true) {
        checkCancelled();
        pollfd descriptor{STDIN_FILENO, POLLIN, 0};
        int ready = poll(&descriptor, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        require(ready >= 0, "input_failed");
        if (!ready) continue;
        checkCancelled();
        ssize_t n = read(STDIN_FILENO, character.data(), 1);
        if (n < 0 && errno == EINTR) continue;
        require(n == 1, "input_failed");
        unsigned char c = character.data()[0];
        if (c == '\n' || c == '\r') break;
        if (c == 4) throw Failure{"input_failed"}; // EOF, even in noncanonical mode.
        if (c == 127 || c == 8) {
            if (input.length) {
                do { --input.length; }
                while (input.length && (input.bytes.data()[input.length] & 0xc0) == 0x80);
                sodium_memzero(input.bytes.data() + input.length,
                               input.bytes.size() - input.length);
            }
        } else {
            require(input.length < input.bytes.size(), "invalid_input");
            input.bytes.data()[input.length++] = c;
        }
        character.clear();
    }
    character.clear();
    terminal.restore();
    std::cout << '\n';
    checkCancelled();
    require(validText(input.field(), input.bytes.size(), password), "invalid_input");
}

bool ownedFile(const struct stat &st, uid_t owner) {
    return S_ISREG(st.st_mode) && st.st_uid == owner && st.st_nlink == 1 &&
           (st.st_mode & 07777) == 0600;
}
struct stat checkFile(int fd) {
    struct stat st{};
    require(fd >= 0 && fstat(fd, &st) == 0 && ownedFile(st, getuid()), "access_denied");
    return st;
}
void checkDirectory(int fd, bool final) {
    struct stat st{};
    require(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode), "access_denied");
    if (final) {
        require(st.st_uid == getuid() && !(st.st_mode & 022), "access_denied");
    } else {
        // Root-owned sticky /tmp may be traversed, but cannot hold the vault directly.
        require((st.st_uid == 0 || st.st_uid == getuid()) &&
                    (!(st.st_mode & 022) || (st.st_uid == 0 && (st.st_mode & S_ISVTX))),
                "access_denied");
    }
}
struct Location {
    Descriptor directory;
    std::string name;
};
Location resolveLocation(const std::string &path) {
    require(!path.empty() && path.size() <= 3000 && path.back() != '/', "invalid_input");
    for (unsigned char c : path)
        require(c >= 32 && c < 127 && c != '\\', "invalid_input");
    Descriptor dir(open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    require(dir.value >= 0, "access_denied");
    size_t cursor = path[0] == '/' ? 1 : 0;
    while (true) {
        size_t slash = path.find('/', cursor);
        std::string part = path.substr(cursor, slash == std::string::npos ? slash : slash - cursor);
        require(!part.empty() && part != "..", "invalid_input");
        if (slash == std::string::npos) {
            require(part != "." && part.size() <= 180, "invalid_input");
            checkDirectory(dir.value, true);
            return {std::move(dir), part};
        }
        checkDirectory(dir.value, false);
        if (part != ".") {
            Descriptor next(openat(dir.value, part.c_str(),
                                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            require(next.value >= 0, "access_denied");
            dir = std::move(next);
        }
        cursor = slash + 1;
    }
}
Descriptor openOwned(int dir, const std::string &name, int flags) {
    Descriptor fd(openat(dir, name.c_str(), flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600));
    checkFile(fd.value);
    return fd;
}
void writeAll(int fd, const unsigned char *data, size_t length, bool cancellable = true) {
    size_t cursor = 0;
    while (cursor < length) {
        if (cancellable) checkCancelled();
        ssize_t n = write(fd, data + cursor, length - cursor);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "io_failed");
        cursor += static_cast<size_t>(n);
    }
}
void syncFile(int fd) {
    int result;
    do { result = fsync(fd); } while (result < 0 && errno == EINTR);
    require(result == 0, "io_failed");
}

struct Audit {
    Descriptor file;
    const char *command;
    Audit(int dir, const std::string &name, const char *operation)
        : file(openOwned(dir, name + ".audit.jsonl", O_WRONLY | O_CREAT | O_APPEND)),
          command(operation) {}
    void event(const char *name, const char *outcome) {
        checkFile(file.value);
        // All strings are hard-coded enums, not argv, user fields or exception text.
        std::string line = "{\"time\":" + std::to_string(std::time(nullptr)) +
            ",\"uid\":" + std::to_string(getuid()) + ",\"pid\":" + std::to_string(getpid()) +
            ",\"command\":\"" + command + "\",\"event\":\"" + name +
            "\",\"outcome\":\"" + outcome + "\"}\n";
        writeAll(file.value, reinterpret_cast<const unsigned char *>(line.data()), line.size(), false);
        syncFile(file.value);
    }
};

void appendInteger(Bytes &b, uint64_t n, size_t count) {
    while (count--) { b.push_back(n & 255); n >>= 8; }
}
uint64_t readInteger(Field data, size_t &cursor, size_t count) {
    require(count <= 8 && cursor <= data.size && count <= data.size - cursor, "invalid_vault");
    uint64_t result = 0;
    for (size_t i = 0; i < count; ++i) result |= uint64_t(data.data[cursor++]) << (8 * i);
    return result;
}
struct Entry { Field service, username, password; };
struct Vault {
    SecureBuffer key{32};
    SecureBuffer plaintext{LIMIT};
    size_t length = 0;
    std::vector<Entry> entries; // Non-owning views, never copies of secrets.
    bool authenticated = false;
};
void parseEntries(Vault &vault) {
    vault.entries.clear();
    Field payload{vault.plaintext.data(), vault.length};
    size_t cursor = 0;
    size_t count = readInteger(payload, cursor, 4);
    require(count <= MAX_ENTRIES, "invalid_vault");
    vault.entries.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        Entry entry{};
        for (Field *field : {&entry.service, &entry.username, &entry.password}) {
            size_t length = readInteger(payload, cursor, 4);
            require(length <= payload.size - cursor, "invalid_vault");
            *field = {payload.data + cursor, length};
            bool secret = field == &entry.password;
            require(validText(*field, secret ? 4096 : 256, secret), "invalid_vault");
            cursor += length;
        }
        for (const auto &previous : vault.entries)
            require(!equal(previous.service, entry.service), "invalid_vault");
        vault.entries.push_back(entry);
        checkCancelled();
    }
    require(cursor == payload.size, "invalid_vault");
}
Bytes readVaultFile(int fd) {
    struct stat st = checkFile(fd);
    require(st.st_size >= static_cast<off_t>(HEADER + 16 + 4) &&
                st.st_size <= static_cast<off_t>(LIMIT), "invalid_vault");
    Bytes data(static_cast<size_t>(st.st_size));
    size_t cursor = 0;
    while (cursor < data.size()) {
        checkCancelled();
        ssize_t n = read(fd, data.data() + cursor, data.size() - cursor);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "io_failed");
        cursor += static_cast<size_t>(n);
    }
    return data;
}
void validateHeader(const Bytes &header) {
    require(header.size() == HEADER && std::memcmp(header.data(), "PMGR\1\1", 6) == 0,
            "invalid_vault");
    size_t position = 6;
    require(readInteger({header.data(), header.size()}, position, 8) == KDF_OPS &&
                readInteger({header.data(), header.size()}, position, 8) == KDF_MEMORY,
            "invalid_vault");
}
void deriveKey(Vault &vault, const Bytes &header, Input &master) {
    validateHeader(header);
    checkCancelled(); testPoint("before_kdf"); checkCancelled();
    int result = crypto_pwhash(vault.key.data(), 32,
        reinterpret_cast<const char *>(master.bytes.data()), master.length,
        header.data() + SALT_OFFSET, KDF_OPS, KDF_MEMORY, crypto_pwhash_ALG_ARGON2ID13);
    master.bytes.clear(); master.length = 0;
    checkCancelled();
    require(result == 0, "memory_failed");
}
void unlockVault(Vault &vault, const Bytes &header, const Bytes &file) {
    unsigned long long length = 0;
    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        vault.plaintext.data(), &length, nullptr, file.data() + HEADER,
        file.size() - HEADER, header.data(), header.size(),
        header.data() + NONCE_OFFSET, vault.key.data());
    require(result == 0, "authentication_failed");
    vault.length = static_cast<size_t>(length);
    parseEntries(vault);
    vault.authenticated = true;
}

class Storage {
    Location location_;
    Descriptor lock_, original_;
    struct stat identity_{};
public:
    explicit Storage(Location location)
        : location_(std::move(location)),
          lock_(openOwned(directory(), name() + ".lock", O_RDWR | O_CREAT)) {
        require(flock(lock_.value, LOCK_EX | LOCK_NB) == 0, "access_denied");
    }
    int directory() const { return location_.directory.value; }
    const std::string &name() const { return location_.name; }
    void authorize(bool create) {
        require(getuid() == geteuid() && getgid() == getegid(), "access_denied");
        checkDirectory(directory(), true);
        struct stat heldLock = checkFile(lock_.value), currentLock{}, current{};
        require(fstatat(directory(), (name() + ".lock").c_str(), &currentLock,
                        AT_SYMLINK_NOFOLLOW) == 0 && heldLock.st_dev == currentLock.st_dev &&
                    heldLock.st_ino == currentLock.st_ino, "access_denied");
        int result = fstatat(directory(), name().c_str(), &current, AT_SYMLINK_NOFOLLOW);
        if (create) require(result < 0 && errno == ENOENT, "access_denied");
        else {
            require(result == 0 && ownedFile(current, getuid()), "access_denied");
            if (original_.value >= 0) {
                checkFile(original_.value);
                require(identity_.st_ino == current.st_ino && identity_.st_dev == current.st_dev,
                        "access_denied");
            }
        }
    }
    Bytes read() {
        authorize(false);
        original_ = openOwned(directory(), name(), O_RDONLY);
        identity_ = checkFile(original_.value);
        authorize(false);
        return readVaultFile(original_.value);
    }
    void save(Bytes &header, Vault &vault, bool create, bool &committed) {
        require(vault.authenticated, "access_denied");
        authorize(create);
        size_t length = 4;
        for (const auto &e : vault.entries) {
            size_t addition = 12 + e.service.size + e.username.size + e.password.size;
            require(addition <= LIMIT - HEADER - 16 - length, "invalid_input");
            length += addition;
        }
        SecureBuffer payload(length);
        size_t cursor = 0;
        auto putInteger = [&](uint64_t n) {
            for (size_t i = 0; i < 4; ++i) { payload.data()[cursor++] = n & 255; n >>= 8; }
        };
        putInteger(vault.entries.size());
        for (const auto &e : vault.entries) {
            for (Field f : {e.service, e.username, e.password}) {
                putInteger(f.size);
                std::memcpy(payload.data() + cursor, f.data, f.size); cursor += f.size;
            }
            checkCancelled();
        }
        randombytes_buf(header.data() + NONCE_OFFSET, 24);
        Bytes encrypted = header;
        encrypted.resize(HEADER + length + 16);
        unsigned long long written = 0;
        require(crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted.data() + HEADER, &written, payload.data(), length,
            header.data(), header.size(), nullptr, header.data() + NONCE_OFFSET,
            vault.key.data()) == 0, "crypto_failed");
        payload.clear();
        checkCancelled();
        std::array<unsigned char, 16> random{};
        std::array<char, 33> hex{};
        randombytes_buf(random.data(), random.size());
        sodium_bin2hex(hex.data(), hex.size(), random.data(), random.size());
        std::string temp = name() + ".tmp." + hex.data();
        Descriptor fd = openOwned(directory(), temp, O_WRONLY | O_CREAT | O_EXCL);
        // The private directory and O_EXCL prevent another UID supplying the temp file.
        struct TempCleanup {
            int dir; const std::string &name;
            ~TempCleanup() { unlinkat(dir, name.c_str(), 0); }
        } cleanup{directory(), temp};
        testPoint("temp_created");
        writeAll(fd.value, encrypted.data(), encrypted.size());
        testPoint("before_sync"); syncFile(fd.value);
        testPoint("before_commit"); checkCancelled();
        authorize(create);
        checkCancelled();
        if (create) require(linkat(directory(), temp.c_str(), directory(), name().c_str(), 0) == 0,
                            "io_failed");
        else require(renameat(directory(), temp.c_str(), directory(), name().c_str()) == 0,
                     "io_failed");
        committed = true;
        // Do not interrupt between atomic commit, temp cleanup and directory sync.
        if (create) require(unlinkat(directory(), temp.c_str(), 0) == 0, "io_failed");
        testPoint("after_commit");
        syncFile(directory());
        checkCancelled();
    }
};

const char *knownCommand(const char *input) {
    for (const char *command : {"init", "add", "list", "update", "delete"})
        if (std::strcmp(input, command) == 0) return command;
    return nullptr;
}
void execute(Storage &storage, Audit &audit, const char *command, bool &committed) {
    bool create = std::strcmp(command, "init") == 0;
    storage.authorize(create);
    Vault vault;
    Bytes header, file;
    if (!create) {
        file = storage.read();
        header.assign(file.begin(), file.begin() + HEADER);
        validateHeader(header); // Bound KDF cost before processing secrets.
    }
    Input master(4096);
    readInput("Master password: ", master, true);
    if (create) {
        require(master.length >= 12, "invalid_input");
        Input confirm(4096);
        readInput("Confirm master password: ", confirm, true);
        require(master.length == confirm.length &&
                    sodium_memcmp(master.bytes.data(), confirm.bytes.data(), master.length) == 0,
                "authentication_failed");
        confirm.bytes.clear();
        header = {'P', 'M', 'G', 'R', 1, 1};
        appendInteger(header, KDF_OPS, 8); appendInteger(header, KDF_MEMORY, 8);
        header.resize(HEADER); randombytes_buf(header.data() + SALT_OFFSET, 16);
    }
    deriveKey(vault, header, master);
    if (create) vault.authenticated = true;
    else unlockVault(vault, header, file);
    testPoint("after_unlock"); checkCancelled();
    audit.event("authentication", "success");
    // Every record operation requires both successful authentication and OS ownership.
    require(vault.authenticated, "access_denied");
    storage.authorize(create);
    if (std::strcmp(command, "list") == 0) {
        std::cout << "Service | Username | Password\n";
        for (const auto &entry : vault.entries) {
            checkCancelled();
            std::cout.write(reinterpret_cast<const char *>(entry.service.data), entry.service.size);
            std::cout << " | ";
            std::cout.write(reinterpret_cast<const char *>(entry.username.data), entry.username.size);
            std::cout << " | [hidden]\n";
        }
        std::cout << vault.entries.size() << " entries\n" << std::flush;
        checkCancelled(); require(bool(std::cout), "io_failed");
        return;
    }
    Input service(256), username(256), password(4096);
    if (!create) {
        readInput("Service: ", service);
        auto entry = std::find_if(vault.entries.begin(), vault.entries.end(),
            [&](const Entry &candidate) { return equal(candidate.service, service.field()); });
        if (std::strcmp(command, "add") == 0) {
            require(entry == vault.entries.end() && vault.entries.size() < MAX_ENTRIES, "invalid_input");
            vault.entries.push_back({service.field(), {}, {}});
            entry = vault.entries.end() - 1;
        } else require(entry != vault.entries.end(), "invalid_input");
        if (std::strcmp(command, "delete") == 0) vault.entries.erase(entry);
        else {
            readInput("Username: ", username);
            readInput("Entry password: ", password, true);
            entry->username = username.field(); entry->password = password.field();
        }
    }
    audit.event("save_started", "pending");
    storage.save(header, vault, create, committed);
}

#ifndef PM_NO_MAIN
int main(int argc, char **argv) {
    bool committed = false;
    try {
        require(sodium_init() >= 0, "setup_failed");
        rlimit limit{0, 0};
        require(setrlimit(RLIMIT_CORE, &limit) == 0, "setup_failed");
        require(getuid() == geteuid() && getgid() == getegid(), "access_denied");
        umask(077); installSignals();
        if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
            std::cout << "Usage: ./pm <init|add|list|update|delete> <vault-file>\n"
                         "All fields use hidden input. Passwords are never displayed.\n";
            return 0;
        }
        require(argc == 3, "invalid_input");
        const char *command = knownCommand(argv[1]);
        require(command != nullptr, "invalid_input");
        Storage storage(resolveLocation(argv[2]));
        Audit audit(storage.directory(), storage.name(), command);
        try {
            audit.event("operation_started", "pending");
            execute(storage, audit, command, committed);
            checkCancelled(); audit.event("operation_finished", "success");
            if (committed) std::cout << "Saved successfully. Passwords remain hidden.\n";
        } catch (const Cancelled &) {
            try { audit.event("interrupted", committed ? "committed" : "not_committed"); } catch (...) {}
            throw;
        } catch (const Failure &failure) {
            try {
                audit.event(std::strcmp(failure.code, "authentication_failed") == 0 ?
                            "authentication" : "operation_finished", committed ? "committed_error" : "failure");
            } catch (...) {}
            throw;
        } catch (...) {
            try { audit.event("operation_finished", committed ? "committed_error" : "failure"); } catch (...) {}
            throw;
        }
    } catch (const Cancelled &) {
        std::cerr << (committed ? "\nInterrupted after saving. Changes were saved.\n" :
                                  "\nInterrupted. No changes were saved.\n");
        return 128 + (stopSignal ? stopSignal : SIGINT);
    } catch (...) {
        std::cerr << (committed ? "Operation may have completed. Check the vault before retrying.\n" :
                                  "Operation failed. Check your input, credentials and access permissions.\n");
        return 1;
    }
    return 0;
}
#endif
