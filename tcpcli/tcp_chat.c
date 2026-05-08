//go:build ignore

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include "toxcore/TCP_client.h"
#include "toxcore/TCP_common.h"
#include "toxcore/crypto_core.h"
#include "toxcore/network.h"
#include "toxcore/mono_time.h"
#include "toxcore/logger.h"
#include "toxcore/mem.h"
#include "toxcore/ccompat.h"
#include "toxcore/os_memory.h"
#include "toxcore/os_random.h"
#include "toxcore/os_network.h"
#include "toxcore/net_profile.h"

typedef struct {
    uint8_t  peer_pk[CRYPTO_PUBLIC_KEY_SIZE];
    bool     have_peer;
    bool     need_greeting;
    uint8_t  self_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t  self_sk[CRYPTO_SECRET_KEY_SIZE];
    TCP_Client_Connection *conn;
    Logger  *logger;
    Mono_Time *mono_time;
    bool     running;
} NodeState;

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

static const char *tcp_status_str(TCP_Client_Status st)
{
    switch (st) {
        case TCP_CLIENT_NO_STATUS:    return "未连接";
        case TCP_CLIENT_CONNECTING:   return "连接中";
        case TCP_CLIENT_UNCONFIRMED:  return "等待确认";
        case TCP_CLIENT_CONFIRMED:    return "已连接";
        case TCP_CLIENT_DISCONNECTED: return "已断开";
        default:                      return "未知";
    }
}

static void log_cb(void *context, Logger_Level level, const char *file,
                   uint32_t line, const char *func, const char *message,
                   void *userdata)
{
    (void)context;
    (void)userdata;
}

static int on_oob_data(void *object, const uint8_t *public_key,
                       const uint8_t *data, uint16_t length, void *userdata)
{
    NodeState *st = (NodeState *)object;
    (void)userdata;

    char hex[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    bin_to_hex(public_key, CRYPTO_PUBLIC_KEY_SIZE, hex);
    fprintf(stderr, "[oob_recv] from=%s len=%u\n", hex, length);

    if (!st->have_peer) {
        memcpy(st->peer_pk, public_key, CRYPTO_PUBLIC_KEY_SIZE);
        st->have_peer = true;
        printf("\n[系统] 收到来自 %s 的消息，已保存为聊天对象\n", hex);
    }

    printf("\n[对端] %.*s\n> ", (int)length, data);
    fflush(stdout);
    return 0;
}

/* ====== 密钥文件读写 ====== */

static int save_keys(const char *path, const uint8_t *pk, const uint8_t *sk)
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

static int load_keys(const char *path, uint8_t *pk, uint8_t *sk)
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

/* ====== 节点进程 ====== */

static int run_node(const char *relay_ip, uint16_t relay_port,
                    const char *relay_hex, const char *key_file,
                    const char *peer_hex)
{
    const Memory *mem = os_memory();
    const Random *rng = os_random();
    const Network *ns = os_network();
    Logger *logger = logger_new(mem);
    logger_callback_log(logger, log_cb, NULL, NULL);
    Mono_Time *mono_time = mono_time_new(mem, NULL, NULL);

    /* 加载或生成密钥 */
    NodeState state;
    memset(&state, 0, sizeof(state));

    if (load_keys(key_file, state.self_pk, state.self_sk) == -1) {
        crypto_new_keypair(rng, state.self_pk, state.self_sk);
        save_keys(key_file, state.self_pk, state.self_sk);
        printf("已生成新密钥，保存到 %s\n", key_file);
    } else {
        printf("已加载密钥文件 %s\n", key_file);
    }

    char self_hex[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
    bin_to_hex(state.self_pk, CRYPTO_PUBLIC_KEY_SIZE, self_hex);
    printf("我的公钥: %s\n", self_hex);
    fflush(stdout);

    IP_Port relay_ip_port;
    memset(&relay_ip_port, 0, sizeof(relay_ip_port));
    relay_ip_port.ip.family = net_family_ipv4();
    if (!addr_parse_ip(relay_ip, &relay_ip_port.ip)) {
        fprintf(stderr, "无法解析中继地址: %s\n", relay_ip);
        return 1;
    }
    relay_ip_port.port = net_htons(relay_port);

    uint8_t relay_pk[CRYPTO_PUBLIC_KEY_SIZE];
    if (hex_to_bin(relay_hex, relay_pk, CRYPTO_PUBLIC_KEY_SIZE)
            != CRYPTO_PUBLIC_KEY_SIZE) {
        fprintf(stderr, "无效的中继公钥\n");
        return 1;
    }

    printf("正在连接中继 %s:%u ...\n", relay_ip, relay_port);
    fflush(stdout);

    state.conn = new_tcp_connection(
        logger, mem, mono_time, rng, ns,
        &relay_ip_port, relay_pk, state.self_pk, state.self_sk, NULL, NULL);

    if (state.conn == nullptr) {
        fprintf(stderr, "连接中继失败\n");
        return 1;
    }

    uint64_t start = mono_time_get(mono_time);
    while (tcp_con_status(state.conn) != TCP_CLIENT_CONFIRMED) {
        mono_time_update(mono_time);
        do_tcp_connection(logger, mono_time, state.conn, NULL);
        if (mono_time_get(mono_time) - start > TCP_CONNECTION_TIMEOUT) {
            fprintf(stderr, "连接中继超时\n");
            kill_tcp_connection(state.conn);
            return 1;
        }
        usleep(10000);
    }
    printf("已连接中继\n");
    fflush(stdout);

    state.logger    = logger;
    state.mono_time = mono_time;
    state.running   = true;

    if (peer_hex != nullptr) {
        if (hex_to_bin(peer_hex, state.peer_pk, CRYPTO_PUBLIC_KEY_SIZE)
                != CRYPTO_PUBLIC_KEY_SIZE) {
            fprintf(stderr, "无效的对端公钥格式\n");
            kill_tcp_connection(state.conn);
            return 1;
        }
        state.have_peer    = true;
        state.need_greeting = true;
    }

    oob_data_handler(state.conn, on_oob_data, &state);

    printf("> ");
    fflush(stdout);

    while (state.running) {
        mono_time_update(mono_time);

        if (state.need_greeting) {
            const char *g = "hello";
            int ret = send_oob_packet(logger, state.conn, state.peer_pk,
                                       (const uint8_t *)g, strlen(g));
            if (ret == 1) {
                state.need_greeting = false;
            } else {
                printf("\n[系统] 发送失败(ret=%d, status=%s, msg=%s)\n> ",
                       ret, tcp_status_str(tcp_con_status(state.conn)), g);
                fflush(stdout);
            }
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval tv = { .tv_usec = 10000 };
        int sel = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);

        if (sel > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
            char buf[2048];
            if (fgets(buf, sizeof(buf), stdin)) {
                size_t len = strlen(buf);
                if (len > 0 && buf[len - 1] == '\n')
                    buf[--len] = '\0';
                if (len > 0) {
                    if (strcmp(buf, "/quit") == 0) {
                        printf("[系统] 已退出\n");
                        state.running = false;
                        break;
                    }
                    if (state.have_peer) {
                        uint16_t slen = len > 1024 ? 1024 : (uint16_t)len;
                        int ret = send_oob_packet(logger, state.conn,
                                    state.peer_pk, (const uint8_t *)buf, slen);
                        if (ret != 1) {
                            printf("[系统] 发送失败(ret=%d, status=%s, msg=%.*s)\n",
                                   ret, tcp_status_str(tcp_con_status(state.conn)),
                                   16, buf);
                        }
                    } else {
                        printf("[系统] 等待对方先发消息...\n");
                    }
                }
            } else {
                break;
            }
            printf("> ");
            fflush(stdout);
        }

        TCP_Client_Status st = tcp_con_status(state.conn);
        do_tcp_connection(logger, mono_time, state.conn, &state);

        if (tcp_con_status(state.conn) == TCP_CLIENT_DISCONNECTED) {
            printf("\n[系统] 与中继断开连接\n");
            break;
        }
    }

    kill_tcp_connection(state.conn);
    mono_time_free(mem, mono_time);
    logger_kill(logger);
    return 0;
}

/* ====== 默认中继（公网） ====== */

#define DEFAULT_RELAY_IP   "43.198.227.166"
#define DEFAULT_RELAY_PORT 3389 // 33445
#define DEFAULT_RELAY_PK   "AD13AB0D434BCE6C83FE2649237183964AE3341D0AFB3BE1694B18505E4E135E"
#define DEFAULT_KEY_FILE   "node.key"

/* ====== 帮助信息 ====== */

static void print_usage(const char *prog)
{
    printf(
        "用法: %s [选项]\n"
        "\n"
        "连接公网 TCP 中继，通过 OOB 消息与对端节点通信。\n"
        "\n"
        "选项:\n"
        "  -h, --help             显示此帮助信息\n"
        "  -r <IP>                中继 IP 地址 (默认: %s)\n"
        "  -P <端口>              中继端口 (默认: %u)\n"
        "  -k <公钥hex>           中继公钥 (默认: %.*s...)\n"
        "  -f <文件>              密钥文件路径 (默认: %s，不存在则自动生成)\n"
        "  -p <公钥hex>           对端公钥 (可选，不指定则等待对方先发消息)\n",
        prog,
        DEFAULT_RELAY_IP,
        DEFAULT_RELAY_PORT,
        16, DEFAULT_RELAY_PK,
        DEFAULT_KEY_FILE);
}

/* ====== 主入口 ====== */

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }

    const char *relay_ip   = DEFAULT_RELAY_IP;
    uint16_t    relay_port = DEFAULT_RELAY_PORT;
    const char *relay_pk   = DEFAULT_RELAY_PK;
    const char *key_file   = DEFAULT_KEY_FILE;
    const char *peer_hex   = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "r:P:k:f:p:")) != -1) {
        switch (opt) {
            case 'r': relay_ip   = optarg; break;
            case 'P': relay_port = (uint16_t)atoi(optarg); break;
            case 'k': relay_pk   = optarg; break;
            case 'f': key_file   = optarg; break;
            case 'p': peer_hex   = optarg; break;
            default:  print_usage(argv[0]); return 1;
        }
    }
    return run_node(relay_ip, relay_port, relay_pk, key_file, peer_hex);
}
