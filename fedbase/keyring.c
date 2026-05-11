#include "keyring.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <blst.h>

static void bin_to_hex(const uint8_t *bin, size_t len, char *hex)
{
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2]     = digits[bin[i] >> 4];
        hex[i * 2 + 1] = digits[bin[i] & 0xF];
    }
    hex[len * 2] = '\0';
}

static int hex_char(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int keyring_hex_to_bin(const char *hex, uint8_t *bin, size_t max_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    len /= 2;
    if (len > max_len) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = hex_char((uint8_t)hex[i * 2]);
        int lo = hex_char((uint8_t)hex[i * 2 + 1]);
        if (hi == -1 || lo == -1) return -1;
        bin[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)len;
}

static int aes256ctr(uint8_t *out, size_t out_len,
                     const uint8_t key[32], const uint8_t iv[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, total = 0;
    static const uint8_t zeros[64] = {0};
    int chunk = out_len > sizeof(zeros) ? sizeof(zeros) : (int)out_len;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)
          && EVP_EncryptUpdate(ctx, out, &len, zeros, chunk);
    if (ok) total += len;
    while (ok && total < (int)out_len) {
        int remain = (int)out_len - total;
        chunk = remain > (int)sizeof(zeros) ? (int)sizeof(zeros) : remain;
        ok = EVP_EncryptUpdate(ctx, out + total, &len, zeros, chunk);
        if (ok) total += len;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? (int)out_len : -1;
}

void keyring_generate(KeyRing *kr)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(kr->seed, 1, KEYRING_SEED_BYTES, f); fclose(f); }
}

int keyring_load(const char *path, KeyRing *kr)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[128]; int found = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "seed=", 5) == 0) {
            if (keyring_hex_to_bin(line + 5, kr->seed, KEYRING_SEED_BYTES) == KEYRING_SEED_BYTES) {
                found = 1; break;
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

int keyring_save(const char *path, const KeyRing *kr)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    char hex[KEYRING_SEED_BYTES * 2 + 1];
    bin_to_hex(kr->seed, KEYRING_SEED_BYTES, hex);
    fprintf(f, "seed=%s\n", hex);
    fclose(f);
    return 0;
}

void keyring_nostr(const KeyRing *kr, secp256k1_context *ctx,
                   secp256k1_keypair *kp, uint8_t pub[KEYRING_KEY_BYTES])
{
    if (!secp256k1_keypair_create(ctx, kp, kr->seed)) return;
    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, kp)) return;
    secp256k1_xonly_pubkey_serialize(ctx, pub, &xonly);
}

void keyring_btdht(const KeyRing *kr,
                   uint8_t seed_out[KEYRING_KEY_BYTES],
                   uint8_t pub[KEYRING_KEY_BYTES])
{
    memcpy(seed_out, kr->seed, KEYRING_KEY_BYTES);
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   kr->seed, KEYRING_KEY_BYTES);
    if (pkey) { size_t len = KEYRING_KEY_BYTES; EVP_PKEY_get_raw_public_key(pkey, pub, &len); EVP_PKEY_free(pkey); }
}

EVP_PKEY *keyring_opendht(const KeyRing *kr)
{
    uint8_t prng[65536];
    if (aes256ctr(prng, sizeof(prng), kr->seed, kr->seed + KEYRING_KEY_BYTES) < 0) return NULL;
    RAND_seed(prng, sizeof(prng));
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;
    EVP_PKEY *pkey = NULL;
    int ok = EVP_PKEY_keygen_init(ctx) > 0
          && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) > 0
          && EVP_PKEY_keygen(ctx, &pkey) > 0;
    EVP_PKEY_CTX_free(ctx);
    return ok ? pkey : NULL;
}

void keyring_tox(const KeyRing *kr,
                 uint8_t sk[KEYRING_KEY_BYTES],
                 uint8_t pk[KEYRING_KEY_BYTES])
{
    memcpy(sk, kr->seed, KEYRING_KEY_BYTES);
    sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, KEYRING_KEY_BYTES);
    if (pkey) { size_t len = KEYRING_KEY_BYTES; EVP_PKEY_get_raw_public_key(pkey, pk, &len); EVP_PKEY_free(pkey); }
}

EVP_PKEY *keyring_i2pd_ed(const KeyRing *kr)
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kr->seed, KEYRING_KEY_BYTES);
}

EVP_PKEY *keyring_i2pd_x(const KeyRing *kr)
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, kr->seed, KEYRING_KEY_BYTES);
}

// ====== internal helpers ======

void keyring_ed25519_pub(const KeyRing *kr, uint8_t pub[KEYRING_KEY_BYTES])
{
    uint8_t seed[KEYRING_KEY_BYTES];
    keyring_btdht(kr, seed, pub);
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

static void sha512(const uint8_t *data, size_t len, uint8_t out[64])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

static void sha256d(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint8_t tmp[32];
    sha256(data, len, tmp);
    sha256(tmp, 32, out);
}

static int base64_encode(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, (int)len);
    (void)BIO_flush(bio);
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    size_t n = buf->length;
    if (n >= out_len) n = out_len - 1;
    memcpy(out, buf->data, n);
    out[n] = '\0';
    BIO_free_all(bio);
    // remove trailing '='
    while (n > 0 && out[n-1] == '=') n--;
    out[n] = '\0';
    return (int)n;
}

static void base32_encode(const uint8_t *data, size_t len, char *out)
{
    static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int i = 0, bits = 0, buffer = 0, pos = 0;
    while (i < (int)len || bits > 0) {
        if (bits < 5 && i < (int)len) {
            buffer = (buffer << 8) | data[i++];
            bits += 8;
        }
        if (bits >= 5) {
            bits -= 5;
            out[pos++] = alphabet[(buffer >> bits) & 0x1F];
        } else if (bits > 0) {
            out[pos++] = alphabet[(buffer << (5 - bits)) & 0x1F];
            bits = 0;
        }
    }
    out[pos] = '\0';
}

static const char *ygg_alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";

static void base32_yggdrasil(const uint8_t *data, size_t len, char *out)
{
    int i = 0, bits = 0, buffer = 0, pos = 0;
    while (i < (int)len || bits > 0) {
        if (bits < 5 && i < (int)len) {
            buffer = (buffer << 8) | data[i++];
            bits += 8;
        }
        if (bits >= 5) {
            bits -= 5;
            out[pos++] = ygg_alphabet[(buffer >> bits) & 0x1F];
        } else if (bits > 0) {
            out[pos++] = ygg_alphabet[(buffer << (5 - bits)) & 0x1F];
            bits = 0;
        }
    }
    out[pos] = '\0';
}

static void base58_encode(const uint8_t *data, size_t len, char *out)
{
    static const char *alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    BIGNUM *n = BN_bin2bn(data, (int)len, NULL);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *base = BN_new(); BN_set_word(base, 58);
    BIGNUM *rem = BN_new();
    char tmp[256];
    int pos = 0;
    while (!BN_is_zero(n)) {
        BN_div(n, rem, n, base, ctx);
        tmp[pos++] = alphabet[BN_get_word(rem)];
    }
    for (size_t i = 0; i < len && data[i] == 0; i++) tmp[pos++] = alphabet[0];
    for (int i = 0; i < pos / 2; i++) { char t = tmp[i]; tmp[i] = tmp[pos-1-i]; tmp[pos-1-i] = t; }
    tmp[pos] = '\0';
    strcpy(out, tmp);
    BN_free(rem); BN_free(base); BN_CTX_free(ctx); BN_free(n);
}

static void ripemd160(const uint8_t *data, size_t len, uint8_t out[20])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

static void keccak256_hash(const uint8_t *data, size_t len, uint8_t out[32])
{
    EVP_MD *md = EVP_MD_fetch(NULL, "KECCAK-256", NULL);
    if (!md) { memset(out, 0, 32); return; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
}

// BLAKE2b-256 (RFC 7693, keyed hash mode — used by Hypercore)
#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 32
#define BLAKE2B_ROUNDS 12
static const uint64_t blake2b_iv[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};
static const uint8_t blake2b_sigma[12][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
};

#define BLAKE2B_G(a,b,c,d,x,y) do { \
    a = a + b + x; d = (d ^ a); d = (d >> 32) | (d << 32); \
    c = c + d;     b = (b ^ c); b = (b >> 24) | (b << 40); \
    a = a + b + y; d = (d ^ a); d = (d >> 16) | (d << 48); \
    c = c + d;     b = (b ^ c); b = (b >> 63) | (b << 1);  \
} while(0)

static void blake2b_compress(uint64_t h[8], const uint64_t m[16], uint64_t t[2], int f)
{
    uint64_t v[16];
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[i+8] = blake2b_iv[i];
    v[12] ^= t[0]; v[13] ^= t[1];
    if (f) v[14] ^= (uint64_t)-1;
    for (int r = 0; r < BLAKE2B_ROUNDS; r++) {
        uint64_t *s = (uint64_t *)blake2b_sigma[r];
        BLAKE2B_G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        BLAKE2B_G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        BLAKE2B_G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        BLAKE2B_G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        BLAKE2B_G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        BLAKE2B_G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        BLAKE2B_G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        BLAKE2B_G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) { h[i] ^= v[i]; h[i] ^= v[i+8]; }
}

static void blake2b256_hash(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len, uint8_t out[BLAKE2B_OUTBYTES])
{
    uint64_t h[8], m[16], t[2] = {0, 0};
    uint8_t block[BLAKE2B_BLOCKBYTES];
    int f = 0;

    for (int i = 0; i < 8; i++) h[i] = blake2b_iv[i];
    // parameter block
    uint8_t param[BLAKE2B_BLOCKBYTES] = {0};
    param[0] = BLAKE2B_OUTBYTES;
    if (key && key_len > 0) param[1] = (uint8_t)key_len;
    ((uint64_t *)param)[0] ^= h[0];
    ((uint64_t *)param)[1] ^= h[1];
    for (int i = 0; i < 8; i++) {
        h[i] ^= ((uint64_t *)param)[i];
    }
    // key block
    if (key && key_len > 0) {
        memset(block, 0, BLAKE2B_BLOCKBYTES);
        memcpy(block, key, key_len > BLAKE2B_BLOCKBYTES ? BLAKE2B_BLOCKBYTES : key_len);
        t[0] += BLAKE2B_BLOCKBYTES;
        memcpy(m, block, BLAKE2B_BLOCKBYTES);
        blake2b_compress(h, m, t, 0);
    }
    // data blocks
    size_t offset = 0;
    while (offset < data_len) {
        size_t chunk = data_len - offset;
        if (chunk > BLAKE2B_BLOCKBYTES) chunk = BLAKE2B_BLOCKBYTES;
        memset(block, 0, BLAKE2B_BLOCKBYTES);
        memcpy(block, data + offset, chunk);
        offset += chunk;
        t[0] += chunk;
        if (offset >= data_len) f = 1;
        memcpy(m, block, BLAKE2B_BLOCKBYTES);
        blake2b_compress(h, m, t, f);
    }
    memcpy(out, h, BLAKE2B_OUTBYTES);
}

static void blake2b512_hash(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len, uint8_t out[64])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_blake2b512(), NULL);
    if (key && key_len > 0) EVP_DigestUpdate(ctx, key, key_len);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

static void hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len, uint8_t prk[32])
{
    unsigned int len = 32;
    HMAC(EVP_sha256(), salt, (int)salt_len, ikm, (int)ikm_len, prk, &len);
}

static void hkdf_expand(const uint8_t *prk, size_t prk_len,
                        uint8_t *out, size_t out_len)
{
    uint8_t t[32] = {0};
    uint8_t counter;
    size_t written = 0;
    for (counter = 1; written < out_len; counter++) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, prk, (int)prk_len);
        EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
        if (written > 0) EVP_DigestSignUpdate(ctx, t, 32);
        EVP_DigestSignUpdate(ctx, &counter, 1);
        size_t len = 32;
        EVP_DigestSignFinal(ctx, t, &len);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        size_t copy = out_len - written;
        if (copy > 32) copy = 32;
        memcpy(out + written, t, copy);
        written += copy;
    }
}

static void bitcoin_address(const uint8_t *pubkey_compressed, size_t pk_len, char *out)
{
    uint8_t sha[32]; sha256(pubkey_compressed, pk_len, sha);
    uint8_t ripe[20]; ripemd160(sha, 32, ripe);
    uint8_t payload[21]; payload[0] = 0x00; memcpy(payload + 1, ripe, 20);
    uint8_t cs[32]; sha256d(payload, 21, cs);
    uint8_t full[25]; memcpy(full, payload, 21); memcpy(full + 21, cs, 4);
    base58_encode(full, 25, out);
}

// ====== Group A: Ed25519 protocols ======

void keyring_torv3_onion(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    uint8_t checksum_input[35];
    const char *prefix = ".onion checksum";
    memcpy(checksum_input, prefix, 15);
    memcpy(checksum_input + 15, pub, 32);
    checksum_input[47] = 0x03;
    uint8_t hash[32]; sha256(checksum_input, 48, hash);
    uint8_t addr_data[35];
    memcpy(addr_data, pub, 32);
    addr_data[32] = hash[0]; addr_data[33] = hash[1];
    addr_data[34] = 0x03;
    base32_encode(addr_data, 35, out);
    for (char *p = out; *p; p++) *p = tolower((unsigned char)*p);
    size_t n = strlen(out);
    if (n + 7 < out_len) { memcpy(out + n, ".onion", 7); out[n + 6] = '\0'; }
}

void keyring_torv3_secret(const KeyRing *kr, uint8_t *out)
{
    memcpy(out, kr->seed, 32);
}

void keyring_ssb_feedid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    out[0] = '@';
    int n = base64_encode(pub, 32, out + 1, out_len - 2);
    if (n + 2 + 9 < (int)out_len) { memcpy(out + 1 + n, ".ed25519", 9); out[1 + n + 8] = '\0'; }
}

void keyring_hypercore_dk256(const KeyRing *kr, uint8_t out[32])
{
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    blake2b256_hash((const uint8_t *)"HYPERCORE", 9, pub, 32, out);
}

void keyring_hypercore_dk512(const KeyRing *kr, uint8_t out[64])
{
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    blake2b512_hash((const uint8_t *)"HYPERCORE", 9, pub, 32, out);
}

void keyring_cjdns_ipv6(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    (void)out_len; uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    uint8_t h[64]; sha512(pub, 32, h);
    h[0] = (h[0] & 0x0F) | 0xFC;
    char hex[33]; bin_to_hex(h, 16, hex);
    int pos = 0; out[pos++] = 'f'; out[pos++] = 'c';
    for (int i = 2; i < 32; i += 2) {
        out[pos++] = hex[i]; out[pos++] = hex[i+1];
        if (i < 30) out[pos++] = ':';
    }
    out[pos] = '\0';
}

void keyring_yggdrasil_ipv6(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    uint8_t h[64]; sha512(pub, 32, h);
    char b32[64]; base32_yggdrasil(h + 1, 15, b32);
    if (strlen(b32) > 26) b32[26] = '\0';
    out[0] = '2'; out[1] = '0'; out[2] = '0'; out[3] = ':';
    int pos = 4;
    for (int i = 0; b32[i]; i += 4) {
        for (int j = 0; j < 4 && b32[i+j]; j++) out[pos++] = b32[i+j];
        if (b32[i+4]) out[pos++] = ':';
    }
    out[pos] = '\0';
}

void keyring_nkn_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    uint8_t h[32]; sha256(pub, 32, h);
    bin_to_hex(h, 32, out);
}

void keyring_gnunet_peerid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    uint8_t h[64]; sha512(pub, 32, h);
    bin_to_hex(h, 64, out);
}

void keyring_bitcoin_tor_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_sia_nodekey(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    memcpy(out, "ed25519:", 8);
    bin_to_hex(pub, 32, out + 8);
}
void keyring_tahoe_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    memcpy(out, "v0-", 3);
    base32_encode(pub, 32, out + 3);
}
void keyring_tribler_peerid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    bin_to_hex(pub, 32, out);
}
void keyring_stellar_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    bin_to_hex(pub, 32, out);
}
void keyring_handshake_nodekey(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_oxen_service_nodekey(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_kayaknet_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t pub[32]; keyring_ed25519_pub(kr, pub);
    bin_to_hex(pub, 32, out);
}
void keyring_cardano_kes_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_cardano_vrf_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_urbit_net_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_urbit_crypt_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_tailscale_node_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_tailscale_machine_key(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }
void keyring_tailscale_tlk(const KeyRing *kr, uint8_t *out) { memcpy(out, kr->seed, 32); }

// ====== Group B: secp256k1 protocols ======

void keyring_bitcoin_v2_key(const KeyRing *kr, uint8_t *out)
{
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (secp256k1_keypair_create(ctx, &kp, kr->seed))
        secp256k1_keypair_sec(ctx, out, &kp);
    secp256k1_context_destroy(ctx);
}

void keyring_eth_nodekey_hex(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    uint8_t sk[32]; keyring_bitcoin_v2_key(kr, sk);
    bin_to_hex(sk, 32, out);
}

void keyring_eth_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_keypair_create(ctx, &kp, kr->seed);
    secp256k1_xonly_pubkey xonly;
    secp256k1_keypair_xonly_pub(ctx, &xonly, NULL, &kp);
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    uint8_t raw[65];
    size_t raw_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, raw, &raw_len, &pub, SECP256K1_EC_UNCOMPRESSED);
    bin_to_hex(raw + 1, 64, out);  // skip 0x04 prefix
    secp256k1_context_destroy(ctx);
}

int keyring_eth_enr_nodeid(const KeyRing *kr, uint8_t out[32])
{
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_keypair_create(ctx, &kp, kr->seed);
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    uint8_t raw[65];
    size_t raw_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, raw, &raw_len, &pub, SECP256K1_EC_UNCOMPRESSED);
    keccak256_hash(raw + 1, 64, out);
    secp256k1_context_destroy(ctx);
    return 0;
}

void keyring_lightning_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_keypair_create(ctx, &kp, kr->seed);
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    uint8_t raw[33];
    size_t raw_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, raw, &raw_len, &pub, SECP256K1_EC_COMPRESSED);
    bin_to_hex(raw, 33, out);
    secp256k1_context_destroy(ctx);
}

void keyring_bitmessage_address(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    // signing key: seed[0:32]
    secp256k1_keypair sign_kp;
    secp256k1_keypair_create(ctx, &sign_kp, kr->seed);
    secp256k1_pubkey sign_pub;
    secp256k1_keypair_pub(ctx, &sign_pub, &sign_kp);
    uint8_t sign_raw[65]; size_t slen = 65;
    secp256k1_ec_pubkey_serialize(ctx, sign_raw, &slen, &sign_pub, SECP256K1_EC_UNCOMPRESSED);
    // encryption key: SHA256(seed[32:48])
    uint8_t enc_sk[32]; sha256(kr->seed + 32, 16, enc_sk);
    secp256k1_keypair enc_kp;
    secp256k1_keypair_create(ctx, &enc_kp, enc_sk);
    secp256k1_pubkey enc_pub;
    secp256k1_keypair_pub(ctx, &enc_pub, &enc_kp);
    uint8_t enc_raw[65]; size_t elen = 65;
    secp256k1_ec_pubkey_serialize(ctx, enc_raw, &elen, &enc_pub, SECP256K1_EC_UNCOMPRESSED);
    secp256k1_context_destroy(ctx);
    // merged = sign_pub || enc_pub
    uint8_t merged[130]; memcpy(merged, sign_raw, 65); memcpy(merged + 65, enc_raw, 65);
    uint8_t sha[64]; EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(mctx, merged, 130);
    EVP_DigestFinal_ex(mctx, sha, NULL);
    EVP_MD_CTX_free(mctx);
    uint8_t ripe[20]; ripemd160(sha, 64, ripe);
    uint8_t payload[21]; payload[0] = 0x00; memcpy(payload + 1, ripe, 20);
    uint8_t cs[32]; sha256d(payload, 21, cs);
    uint8_t full[25]; memcpy(full, payload, 21); memcpy(full + 21, cs, 4);
    base58_encode(full, 25, out);
}

void keyring_zeronet_address(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_keypair_create(ctx, &kp, kr->seed);
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    uint8_t raw[33]; size_t raw_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, raw, &raw_len, &pub, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    bitcoin_address(raw, 33, out);
}

void keyring_avalanche_nodeid(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_keypair_create(ctx, &kp, kr->seed);
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    uint8_t raw[33]; size_t raw_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, raw, &raw_len, &pub, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    uint8_t h[32]; sha256(raw, 33, h);
    memcpy(out, "NodeID-", 7);
    base58_encode(h, 20, out + 7);
}

// ====== Group C: RSA protocols ======

int keyring_arweave_address(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    EVP_PKEY *rsa = keyring_opendht(kr);
    if (!rsa) return -1;
    const BIGNUM *n = NULL;
    RSA *rsa_key = EVP_PKEY_get1_RSA(rsa);
    if (rsa_key) { RSA_get0_key(rsa_key, &n, NULL, NULL); }
    else { EVP_PKEY_free(rsa); return -1; }
    int n_len = BN_num_bytes(n);
    uint8_t *n_bytes = malloc(n_len);
    BN_bn2bin(n, n_bytes);
    uint8_t h[32]; sha256(n_bytes, n_len, h);
    // base64url encode
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, h, 32);
    (void)BIO_flush(bio);
    BUF_MEM *buf; BIO_get_mem_ptr(bio, &buf);
    size_t blen = buf->length;
    // base64url (replace + with -, / with _)
    for (size_t i = 0; i < blen; i++) {
        if (buf->data[i] == '+') buf->data[i] = '-';
        else if (buf->data[i] == '/') buf->data[i] = '_';
    }
    size_t copy = blen < out_len - 1 ? blen : out_len - 1;
    memcpy(out, buf->data, copy); out[copy] = '\0';
    // remove padding
    while (copy > 0 && out[copy-1] == '=') copy--;
    out[copy] = '\0';
    BIO_free_all(bio);
    free(n_bytes);
    RSA_free(rsa_key);
    EVP_PKEY_free(rsa);
    return 0;
}

void keyring_storj_identity(const KeyRing *kr, char *out, size_t out_len)
{
    (void)out_len;
    secp256k1_keypair kp;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_keypair_create(ctx, &kp, kr->seed);
    secp256k1_pubkey pub;
    secp256k1_keypair_pub(ctx, &pub, &kp);
    uint8_t raw[33]; size_t raw_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, raw, &raw_len, &pub, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);
    uint8_t h[32]; sha256(raw, 33, h);
    bin_to_hex(h, 32, out);
}

// ====== Group D: BLS12-381 protocols ======

// BLS12-381 group order r
static const char *bls12_381_r_hex =
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

static void bls12_381_keygen(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48])
{
    // key derivation matching Go blsKeyGen:
    //   prk = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", ikm)
    //   okm = HKDF-Expand(prk, 48)
    //   sk = OS2IP(okm) mod r
    //   pk = sk * G1
    static const uint8_t salt[] = "BLS-SIG-KEYGEN-SALT-";
    uint8_t prk[32];
    hkdf_extract(salt, sizeof(salt) - 1, kr->seed, KEYRING_KEY_BYTES, prk);

    uint8_t okm[48];
    hkdf_expand(prk, 32, okm, 48);

    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *okm_bn = BN_bin2bn(okm, 48, NULL);
    BIGNUM *r = BN_new();
    BN_hex2bn(&r, bls12_381_r_hex);
    BIGNUM *sk_bn = BN_new();
    BN_mod(sk_bn, okm_bn, r, bn_ctx);
    BN_bn2binpad(sk_bn, sk, 32);
    BN_free(sk_bn);
    BN_free(r);
    BN_free(okm_bn);
    BN_CTX_free(bn_ctx);

    blst_scalar sk_scalar;
    blst_scalar_from_bendian(&sk_scalar, sk);
    blst_p1 pk_point;
    blst_sk_to_pk_in_g1(&pk_point, &sk_scalar);
    blst_p1_affine pk_affine;
    blst_p1_to_affine(&pk_affine, &pk_point);
    blst_p1_affine_compress(pk, &pk_affine);
}

void keyring_chia_farmer_key(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48])
{
    bls12_381_keygen(kr, sk, pk);
}

void keyring_eth2_validator_key(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48])
{
    bls12_381_keygen(kr, sk, pk);
}

void keyring_avalanche_bls_key(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48])
{
    bls12_381_keygen(kr, sk, pk);
}

// ====== Group E: libp2p ======

static void proto_varint(uint64_t v, uint8_t *out, int *len)
{
    int pos = 0;
    while (v > 0x7F) { out[pos++] = (uint8_t)(v | 0x80); v >>= 7; }
    out[pos++] = (uint8_t)v;
    *len = pos;
}

void keyring_libp2p_peerid(const KeyRing *kr, int kind, char *out, size_t out_len)
{
    uint8_t pubkey_data[600];
    int pubkey_len = 0;
    uint64_t key_type = 1; // Ed25519 default
    switch (kind) {
        case 0: { // Ed25519
            key_type = 1;
            keyring_ed25519_pub(kr, pubkey_data);
            pubkey_len = 32;
            break;
        }
        case 1: { // secp256k1
            key_type = 2;
            secp256k1_keypair kp;
            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            secp256k1_keypair_create(ctx, &kp, kr->seed);
            secp256k1_pubkey pub;
            secp256k1_keypair_pub(ctx, &pub, &kp);
            size_t rlen = 33;
            secp256k1_ec_pubkey_serialize(ctx, pubkey_data, &rlen, &pub, SECP256K1_EC_COMPRESSED);
            pubkey_len = (int)rlen;
            secp256k1_context_destroy(ctx);
            break;
        }
        case 2: { // RSA
            key_type = 0;
            EVP_PKEY *rsa = keyring_opendht(kr);
            if (!rsa) { out[0] = '\0'; return; }
            RSA *rsa_key = EVP_PKEY_get1_RSA(rsa);
            if (rsa_key) {
                const BIGNUM *n;
                RSA_get0_key(rsa_key, &n, NULL, NULL);
                pubkey_len = BN_num_bytes(n);
                BN_bn2bin(n, pubkey_data);
                RSA_free(rsa_key);
            }
            EVP_PKEY_free(rsa);
            break;
        }
        default: { out[0] = '\0'; return; }
    }
    // Build protobuf: field 1=KeyType(varint), field 2=Data(length-delim)
    uint8_t proto[700];
    int pos = 0;
    uint8_t tmp[10]; int tmplen;
    // field 1 varint
    proto_varint(1*8+0, tmp, &tmplen); memcpy(proto+pos, tmp, tmplen); pos += tmplen;  // tag
    proto_varint(key_type, tmp, &tmplen); memcpy(proto+pos, tmp, tmplen); pos += tmplen; // value
    // field 2 length-delim
    proto_varint(2*8+2, tmp, &tmplen); memcpy(proto+pos, tmp, tmplen); pos += tmplen;  // tag
    proto_varint((uint64_t)pubkey_len, tmp, &tmplen); memcpy(proto+pos, tmp, tmplen); pos += tmplen;
    memcpy(proto+pos, pubkey_data, pubkey_len); pos += pubkey_len;
    // Multihash
    if (pos <= 42) {
        uint8_t mh[500];
        int mpos = 0;
        proto_varint(0x00, tmp, &tmplen); memcpy(mh+mpos, tmp, tmplen); mpos += tmplen;
        proto_varint((uint64_t)pos, tmp, &tmplen); memcpy(mh+mpos, tmp, tmplen); mpos += tmplen;
        memcpy(mh+mpos, proto, pos); mpos += pos;
        base58_encode(mh, mpos, out);
    } else {
        uint8_t h[32]; sha256(proto, pos, h);
        uint8_t mh[50];
        int mpos = 0;
        proto_varint(0x12, tmp, &tmplen); memcpy(mh+mpos, tmp, tmplen); mpos += tmplen;
        proto_varint(32, tmp, &tmplen); memcpy(mh+mpos, tmp, tmplen); mpos += tmplen;
        memcpy(mh+mpos, h, 32); mpos += 32;
        base58_encode(mh, mpos, out);
    }
}
