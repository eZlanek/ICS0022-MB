#define PM_TESTING
#define PM_NO_MAIN
#include "../main.cpp"
#include <cassert>
#include <type_traits>

size_t wiped = 0;
void observeWipe(const unsigned char *data, size_t size) {
    assert(sodium_is_zero(data, size) == 1);
    ++wiped;
}
template<class F> void rejects(F action) {
    bool failed = false;
    try { action(); } catch (const Failure &) { failed = true; }
    assert(failed);
}
Field field(const std::string &text) {
    return {reinterpret_cast<const unsigned char *>(text.data()), text.size()};
}
void payloadInteger(Bytes &b, uint64_t n) { appendInteger(b, n, 4); }
void payloadText(Bytes &b, const std::string &text) {
    payloadInteger(b, text.size()); b.insert(b.end(), text.begin(), text.end());
}
Bytes recordPayload(const std::string &service, const std::string &username,
                    const std::string &password) {
    Bytes b; payloadInteger(b, 1);
    payloadText(b, service); payloadText(b, username); payloadText(b, password); return b;
}
void loadPayload(Vault &v, const Bytes &b) {
    assert(b.size() <= LIMIT);
    v.plaintext.clear(); std::memcpy(v.plaintext.data(), b.data(), b.size()); v.length = b.size();
}
int main() {
    assert(sodium_init() >= 0);
    static_assert(!std::is_copy_constructible<SecureBuffer>::value);
    static_assert(!std::is_copy_assignable<SecureBuffer>::value);
    testWipeObserver = observeWipe;
    {
        SecureBuffer original(4096);
        std::memset(original.data(), 0x5a, original.size());
        auto *address = original.data();
        SecureBuffer moved(std::move(original));
        assert(original.data() == nullptr && moved.data() == address);
        SecureBuffer other(32); std::memset(other.data(), 0x33, other.size());
        other = std::move(moved);
        assert(moved.data() == nullptr && other.data() == address);
    }
    size_t before = wiped;
    try { SecureBuffer secret(256); std::memset(secret.data(), 0x77, secret.size()); throw Cancelled{}; }
    catch (const Cancelled &) {}
    assert(wiped > before);
    testLockFailure = true;
    rejects([] { SecureBuffer secret(32); });
    testLockFailure = false;
    std::cout << "PASS secure buffers: zero-before-free, moves, exception cleanup, lock failure\n";

    assert(validText(field("mail"), 256));
    assert(validText(field("почта-é-😀"), 256));
    assert(validText(field("$(touch harmless);`id`"), 256));
    assert(validText(field(std::string(256, 'a')), 256));
    assert(!validText(field(std::string(257, 'a')), 256));
    assert(validText(field(std::string(4096, 'p')), 4096, true));
    assert(!validText(field(std::string(4097, 'p')), 4096, true));
    for (const std::string &invalid : {std::string(""), std::string(" leading"),
             std::string("trailing "), std::string("x|y"), std::string("a\0b", 3),
             std::string("a\x1b[31m"), std::string("x\x7f"), std::string("\xc0\xaf"),
             std::string("\xed\xa0\x80"), std::string("\xf4\x90\x80\x80"),
             std::string("\xe2\x80\xae"), std::string("\xc2\x85")})
        assert(!validText(field(invalid), 256));
    struct stat st{}; st.st_mode = S_IFREG | 0600; st.st_uid = 123; st.st_nlink = 1;
    assert(ownedFile(st, 123)); assert(!ownedFile(st, 124));
    st.st_nlink = 2; assert(!ownedFile(st, 123)); st.st_nlink = 1;
    st.st_mode = S_IFREG | 0640; assert(!ownedFile(st, 123));
    st.st_mode = S_IFREG | 04600; assert(!ownedFile(st, 123));
    st.st_mode = S_IFIFO | 0600; assert(!ownedFile(st, 123));
    std::cout << "PASS validation: UTF-8, controls, sizes, metacharacters, UID and permissions\n";

    Vault v;
    Bytes valid = recordPayload("mail", "alice", "Fixture-Secret-123");
    loadPayload(v, valid); parseEntries(v);
    assert(v.entries.size() == 1 && equal(v.entries[0].password, field("Fixture-Secret-123")));
    Bytes invalid = valid; invalid.push_back(0); loadPayload(v, invalid); rejects([&] { parseEntries(v); });
    for (size_t n = 0; n < valid.size(); ++n) {
        loadPayload(v, Bytes(valid.begin(), valid.begin() + n)); rejects([&] { parseEntries(v); });
    }
    invalid = recordPayload("mail", "\x1b[31m", "Fixture-Secret-123");
    loadPayload(v, invalid); rejects([&] { parseEntries(v); });
    invalid.clear(); payloadInteger(invalid, 1001);
    loadPayload(v, invalid); rejects([&] { parseEntries(v); });
    invalid = valid; invalid[4] = 0xff; invalid[5] = 0xff;
    loadPayload(v, invalid); rejects([&] { parseEntries(v); });
    invalid = valid; invalid[0] = 2; invalid.insert(invalid.end(), valid.begin() + 4, valid.end());
    loadPayload(v, invalid); rejects([&] { parseEntries(v); });
    // Random malformed decrypted input exercises bounds checks without invoking the KDF.
    for (size_t n = 0; n < 2000; ++n) {
        Bytes fuzz(randombytes_uniform(512));
        if (!fuzz.empty()) randombytes_buf(fuzz.data(), fuzz.size());
        loadPayload(v, fuzz);
        try { parseEntries(v); } catch (const Failure &) {}
    }
    std::cout << "PASS parser: truncated/oversized/duplicate fields and 2000 malformed payloads\n";

    Bytes header{'P','M','G','R',1,1};
    appendInteger(header, KDF_OPS, 8); appendInteger(header, KDF_MEMORY, 8); header.resize(HEADER);
    randombytes_buf(header.data() + SALT_OFFSET, 16);
    randombytes_buf(header.data() + NONCE_OFFSET, 24);
    validateHeader(header);
    Bytes badHeader = header; badHeader[6] = 255; rejects([&] { validateHeader(badHeader); });
    randombytes_buf(v.key.data(), 32);
    Bytes ciphertext = header; ciphertext.resize(HEADER + valid.size() + 16);
    unsigned long long length = 0;
    assert(crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data() + HEADER, &length,
        valid.data(), valid.size(), header.data(), HEADER, nullptr,
        header.data() + NONCE_OFFSET, v.key.data()) == 0);
    unlockVault(v, header, ciphertext);
    assert(v.authenticated && equal(v.entries[0].password, field("Fixture-Secret-123")));
    ciphertext.back() ^= 1; rejects([&] { unlockVault(v, header, ciphertext); });
    ciphertext.back() ^= 1; badHeader = header; badHeader[22] ^= 1;
    rejects([&] { unlockVault(v, badHeader, ciphertext); });
    std::cout << "PASS crypto: exact decrypted password, tampering and authenticated header\n";

    char directoryTemplate[] = "/tmp/pm-unit-XXXXXX";
    char *created = mkdtemp(directoryTemplate); assert(created);
    std::array<char, 4096> physical{}; assert(realpath(created, physical.data()));
    std::string path = std::string(physical.data()) + "/test.vault";
    {
        Storage storage(resolveLocation(path));
        bool committed = false;
        v.authenticated = false;
        rejects([&] { storage.save(header, v, true, committed); });
        assert(!committed && access(path.c_str(), F_OK) != 0);
    }
    unlink((path + ".lock").c_str()); rmdir(physical.data());
    std::cout << "PASS unauthenticated save is rejected\n";
}
