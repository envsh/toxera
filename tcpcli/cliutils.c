#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void bin_to_hex(const uint8_t *bin, size_t len, char *hex)
{
    for (size_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02X", bin[i]);
    hex[len * 2] = '\0';
}

static int hex_char(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bin(const char *hex, uint8_t *bin, size_t max_len)
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

/* ====== 密钥文件读写 ====== */

// content:
// pk=upper hex
// sk=upper hex

int toxin_save_keys(const char *path, const uint8_t *pk, const uint8_t *sk)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    char hex[65];
    bin_to_hex(pk, 32, hex); fprintf(f, "pk=%s\n", hex);
    bin_to_hex(sk, 32, hex); fprintf(f, "sk=%s\n", hex);
    fclose(f);
    return 0;
}

static bool is_zero(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (buf[i] != 0) return false;
    return true;
}

int toxin_load_keys(const char *path, uint8_t *pk, uint8_t *sk)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int got_pk = 0, got_sk = 0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == 'p' && line[1] == 'k' && line[2] == '='
                && hex_to_bin(line + 3, pk, 32) == 32)
            got_pk = 1;
        else if (line[0] == 's' && line[1] == 'k' && line[2] == '='
                && hex_to_bin(line + 3, sk, 32) == 32)
            got_sk = 1;
    }
    fclose(f);
    if (!got_pk || !got_sk || is_zero(pk, 32) || is_zero(sk, 32))
        return -1;
    return 0;
}
