#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/select.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#define KEY_BYTES   32
#define KEY_HEX_LEN 64
#define SIG_BYTES   64
#define SIG_HEX_LEN 128
#define ID_BYTES    32
#define ID_HEX_LEN  64
#define BUF_SIZE    16384

#define DEFAULT_RELAY   "wss://relay.damus.io"
#define DEFAULT_KIND    22334
#define DEFAULT_KEYFILE "nostr.key"



typedef struct {
    uint8_t  seckey[KEY_BYTES];
    uint8_t  pubkey[KEY_BYTES];
    char     pubkey_hex[KEY_HEX_LEN + 1];
    char     peer_hex[KEY_HEX_LEN + 1];
    bool     have_peer;
    int      kind;
    char     relay_url[512];
    char     app_tag[64];
    secp256k1_context *secp_ctx;
    secp256k1_keypair  keypair;
    CURL    *curl;
    curl_socket_t sockfd;
    bool     running;
} AppState;

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

static void str_to_upper(char *s)
{
    for (; *s; s++) *s = (char)toupper((unsigned char)*s);
}

static int save_key(const char *path, const char *pub_hex, const uint8_t *seckey_raw)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    char sec_hex[KEY_HEX_LEN + 1];
    bin_to_hex(seckey_raw, KEY_BYTES, sec_hex);
    fprintf(f, "pub=%s\nsec=%s\n", pub_hex, sec_hex);
    fclose(f);
    return 0;
}

static int load_key(const char *path, char *pub_hex, uint8_t *seckey)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[128];
    int got_pub = 0, got_sec = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "pub=", 4) == 0 && strlen(line + 4) == KEY_HEX_LEN) {
            strcpy(pub_hex, line + 4);
            got_pub = 1;
        } else if (strncmp(line, "sec=", 4) == 0
                && hex_to_bin(line + 4, seckey, KEY_BYTES) == (int)KEY_BYTES) {
            got_sec = 1;
        }
    }
    fclose(f);
    if (!got_pub || !got_sec) return -1;
    return 0;
}

static int gen_keypair(AppState *st)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(st->seckey, 1, KEY_BYTES, f) != KEY_BYTES) {
        if (f) fclose(f);
        return -1;
    }
    fclose(f);

    if (!secp256k1_keypair_create(st->secp_ctx, &st->keypair, st->seckey))
        return -1;

    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_keypair_xonly_pub(st->secp_ctx, &xonly, NULL, &st->keypair))
        return -1;

    secp256k1_xonly_pubkey_serialize(st->secp_ctx, st->pubkey, &xonly);
    bin_to_hex(st->pubkey, KEY_BYTES, st->pubkey_hex);
    return 0;
}

static char *build_signed_event(AppState *st, const char *content)
{
    long created_at = (long)time(NULL);

    cJSON *tags = cJSON_CreateArray();
    if (st->have_peer) {
        cJSON *p = cJSON_CreateArray();
        cJSON_AddItemToArray(p, cJSON_CreateString("p"));
        cJSON_AddItemToArray(p, cJSON_CreateString(st->peer_hex));
        cJSON_AddItemToArray(tags, p);
    }
    if (st->app_tag[0] != '\0') {
        cJSON *a = cJSON_CreateArray();
        cJSON_AddItemToArray(a, cJSON_CreateString("app"));
        cJSON_AddItemToArray(a, cJSON_CreateString(st->app_tag));
        cJSON_AddItemToArray(tags, a);
    }

    cJSON *id_arr = cJSON_CreateArray();
    cJSON_AddItemToArray(id_arr, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(id_arr, cJSON_CreateString(st->pubkey_hex));
    cJSON_AddItemToArray(id_arr, cJSON_CreateNumber((double)created_at));
    cJSON_AddItemToArray(id_arr, cJSON_CreateNumber((double)st->kind));
    cJSON_AddItemToArray(id_arr, cJSON_Duplicate(tags, 1));
    cJSON_AddItemToArray(id_arr, cJSON_CreateString(content));

    char *ser = cJSON_PrintUnformatted(id_arr);
    cJSON_Delete(id_arr);

    uint8_t id_hash[ID_BYTES];
    SHA256((const unsigned char *)ser, strlen(ser), id_hash);
    free(ser);

    uint8_t aux_rand[32];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(aux_rand, 1, 32, f);
        fclose(f);
    } else {
        memset(aux_rand, 0, 32);
    }

    uint8_t sig[SIG_BYTES];
    secp256k1_schnorrsig_sign32(st->secp_ctx, sig, id_hash, &st->keypair, aux_rand);

    char id_hex[ID_HEX_LEN + 1];
    char sig_hex[SIG_HEX_LEN + 1];
    bin_to_hex(id_hash, ID_BYTES, id_hex);
    bin_to_hex(sig, SIG_BYTES, sig_hex);

    cJSON *ev = cJSON_CreateObject();
    cJSON_AddStringToObject(ev, "id", id_hex);
    cJSON_AddStringToObject(ev, "pubkey", st->pubkey_hex);
    cJSON_AddNumberToObject(ev, "created_at", (double)created_at);
    cJSON_AddNumberToObject(ev, "kind", (double)st->kind);
    cJSON_AddItemToObject(ev, "tags", tags);
    cJSON_AddStringToObject(ev, "content", content);
    cJSON_AddStringToObject(ev, "sig", sig_hex);

    cJSON *msg = cJSON_CreateArray();
    cJSON_AddItemToArray(msg, cJSON_CreateString("EVENT"));
    cJSON_AddItemToArray(msg, ev);

    char *json = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    return json;
}

static char *build_sub_json(AppState *st)
{
    cJSON *filter = cJSON_CreateObject();
    cJSON *kinds = cJSON_CreateArray();
    cJSON_AddItemToArray(kinds, cJSON_CreateNumber((double)st->kind));
    cJSON_AddItemToObject(filter, "kinds", kinds);

    if (st->have_peer) {
        cJSON *p = cJSON_CreateArray();
        cJSON_AddItemToArray(p, cJSON_CreateString(st->pubkey_hex));
        cJSON_AddItemToObject(filter, "#p", p);
    }

    cJSON *msg = cJSON_CreateArray();
    cJSON_AddItemToArray(msg, cJSON_CreateString("REQ"));
    cJSON_AddItemToArray(msg, cJSON_CreateString("main"));
    cJSON_AddItemToArray(msg, filter);

    char *json = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    return json;
}

static int ws_connect(AppState *st)
{
    curl_easy_setopt(st->curl, CURLOPT_URL, st->relay_url);
    curl_easy_setopt(st->curl, CURLOPT_CONNECT_ONLY, 2L);
    curl_easy_setopt(st->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    CURLcode res = curl_easy_perform(st->curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "连接失败: %s\n", curl_easy_strerror(res));
        return -1;
    }

    curl_easy_getinfo(st->curl, CURLINFO_ACTIVESOCKET, &st->sockfd);
    int fl = fcntl(st->sockfd, F_GETFL, 0);
    fcntl(st->sockfd, F_SETFL, fl | O_NONBLOCK);
    return 0;
}

static int ws_send(AppState *st, const char *json)
{
    size_t len = strlen(json);
    size_t sent;
    CURLcode res = curl_ws_send(st->curl, json, len, &sent, 0, CURLWS_TEXT);
    if (res != CURLE_OK)
        return -1;
    return (int)sent;
}

static void handle_msg(AppState *st, const char *buf, size_t len)
{
    (void)len;
    printf("<<< %.*s\n", (int)len > 500 ? 500 : (int)len, buf);
    cJSON *msg = cJSON_Parse(buf);
    if (!msg || !cJSON_IsArray(msg)) {
        cJSON_Delete(msg);
        return;
    }

    int count = cJSON_GetArraySize(msg);
    if (count < 1) {
        cJSON_Delete(msg);
        return;
    }

    cJSON *type_item = cJSON_GetArrayItem(msg, 0);
    if (!cJSON_IsString(type_item)) {
        cJSON_Delete(msg);
        return;
    }

    const char *type = type_item->valuestring;

    if (strcmp(type, "EVENT") == 0 && count >= 3) {
        cJSON *event = cJSON_GetArrayItem(msg, 2);
        if (!event) { cJSON_Delete(msg); return; }
        cJSON *pk = cJSON_GetObjectItem(event, "pubkey");
        cJSON *ct = cJSON_GetObjectItem(event, "content");
        cJSON *ev_kind = cJSON_GetObjectItem(event, "kind");
        if (!cJSON_IsString(pk) || !cJSON_IsString(ct) || !cJSON_IsNumber(ev_kind))
            { cJSON_Delete(msg); return; }
        if ((int)ev_kind->valuedouble != st->kind)
            { cJSON_Delete(msg); return; }
        if (strcmp(pk->valuestring, st->pubkey_hex) == 0)
            { cJSON_Delete(msg); return; }

        if (st->app_tag[0] != '\0') {
            cJSON *tags = cJSON_GetObjectItem(event, "tags");
            bool found_app = false;
            if (cJSON_IsArray(tags)) {
                int tcnt = cJSON_GetArraySize(tags);
                for (int i = 0; i < tcnt; i++) {
                    cJSON *t = cJSON_GetArrayItem(tags, i);
                    if (!cJSON_IsArray(t) || cJSON_GetArraySize(t) < 2) continue;
                    cJSON *t0 = cJSON_GetArrayItem(t, 0);
                    cJSON *t1 = cJSON_GetArrayItem(t, 1);
                    if (cJSON_IsString(t0) && cJSON_IsString(t1)
                            && strcmp(t0->valuestring, "app") == 0
                            && strcmp(t1->valuestring, st->app_tag) == 0)
                        { found_app = true; break; }
                }
            }
            if (!found_app) { cJSON_Delete(msg); return; }
        }

        char display[KEY_HEX_LEN + 1];
        strncpy(display, pk->valuestring, KEY_HEX_LEN);
        display[KEY_HEX_LEN] = '\0';
        str_to_upper(display);
        printf("\n[%.8s] %s\n> ", display, ct->valuestring);
        fflush(stdout);

    } else if (strcmp(type, "OK") == 0 && count >= 4) {
        cJSON *id_item = cJSON_GetArrayItem(msg, 1);
        cJSON *ok_item = cJSON_GetArrayItem(msg, 2);
        cJSON *msg_item = cJSON_GetArrayItem(msg, 3);
        if (cJSON_IsString(id_item) && cJSON_IsBool(ok_item) && cJSON_IsString(msg_item)) {
            printf("\n[relay OK] %s %s\n> ", 
                   ok_item->valueint ? "ok" : "rejected",
                   msg_item->valuestring);
            fflush(stdout);
        }

    } else if (strcmp(type, "NOTICE") == 0 && count >= 2) {
        cJSON *notice = cJSON_GetArrayItem(msg, 1);
        if (cJSON_IsString(notice)) {
            printf("\n[relay NOTICE] %s\n> ", notice->valuestring);
            fflush(stdout);
        }

    } else if (strcmp(type, "CLOSED") == 0 && count >= 3) {
        cJSON *reason = cJSON_GetArrayItem(msg, 2);
        if (cJSON_IsString(reason)) {
            printf("\n[relay CLOSED] %s\n", reason->valuestring);
            fflush(stdout);
        }
        st->running = false;
    }

    cJSON_Delete(msg);
}

static void chat_loop(AppState *st)
{
    char *sub = build_sub_json(st);
    printf(">>> %s\n", sub);
    ws_send(st, sub);
    free(sub);

    printf("> ");
    fflush(stdout);

    while (st->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(st->sockfd, &fds);
        int nfds = (st->sockfd > STDIN_FILENO ? st->sockfd : STDIN_FILENO) + 1;

        int ret = select(nfds, &fds, NULL, NULL, NULL);
        if (ret < 0) break;

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            char buf[4096];
            if (fgets(buf, sizeof(buf), stdin)) {
                size_t len = strlen(buf);
                if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';
                if (len == 0) { printf("> "); fflush(stdout); continue; }
                if (strcmp(buf, "/quit") == 0) {
                    printf("[系统] 已退出\n");
                    st->running = false;
                    break;
                }
                char *json = build_signed_event(st, buf);
                printf(">>> %s\n", json);
                int sent = ws_send(st, json);
                if (sent < 0) {
                    printf("[系统] 发送失败\n");
                }
                free(json);
            } else {
                break;
            }
            printf("> ");
            fflush(stdout);
        }

        if (FD_ISSET(st->sockfd, &fds)) {
            char buf[BUF_SIZE];
            size_t recvlen;
            const struct curl_ws_frame *meta;
            CURLcode res = curl_ws_recv(st->curl, buf, sizeof(buf) - 1,
                                        &recvlen, &meta);
            if (res == CURLE_AGAIN) continue;
            if (res != CURLE_OK || recvlen == 0) {
                if (res != CURLE_AGAIN) {
                    printf("\n[系统] 连接断开 (%s)\n", curl_easy_strerror(res));
                    st->running = false;
                    break;
                }
                continue;
            }
            buf[recvlen] = '\0';

            if (meta->flags & CURLWS_TEXT) {
                handle_msg(st, buf, recvlen);
            } else if (meta->flags & CURLWS_CLOSE) {
                printf("\n[系统] 连接关闭\n");
                st->running = false;
                break;
            } else if (meta->flags & CURLWS_PING) {
                curl_ws_send(st->curl, buf, recvlen, &recvlen, 0, CURLWS_PONG);
            }
        }
    }
}

static void print_usage(const char *prog)
{
    printf(
        "用法: %s [选项]\n"
        "\n"
        "通过 WebSocket 连接 Nostr relay，使用 kind 22334 临时事件进行聊天。\n"
        "\n"
        "选项:\n"
        "  -h, --help             显示此帮助信息\n"
        "  -r, --relay  RELAY     WebSocket URL\n"
        "                         默认: %s\n"
        "                         其他: wss://relay.damus.io\n"
        "                               wss://nos.lol\n"
        "  -k, --kind   KIND      事件 kind (默认 %d)\n"
        "  -f, --file   FILE      密钥文件路径 (默认 %s)\n"
        "  -p, --peer   PUBKEY    指定对端公钥 hex\n"
        "                          有: 只收对方消息，发出带 p tag\n"
        "                          无: 收所有该 kind 的消息，发出无 p tag\n"
        "  -a, --app    NAME      应用 tag 名称 (默认空)\n"
        "                          有: 只收发带 [\"app\",NAME] tag 的事件\n"
        "                          无: 不做应用 tag 过滤\n"
        "\n"
        "命令:\n"
        "  /quit                   退出程序\n",
        prog, DEFAULT_RELAY, DEFAULT_KIND, DEFAULT_KEYFILE);
}

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }

    const char *relay_url = DEFAULT_RELAY;
    const char *key_file  = DEFAULT_KEYFILE;
    const char *peer_hex  = NULL;
    const char *app_arg   = NULL;
    int kind = DEFAULT_KIND;

    int opt;
    while ((opt = getopt(argc, argv, "r:k:f:p:a:h")) != -1) {
        switch (opt) {
            case 'r': relay_url = optarg; break;
            case 'k': kind = atoi(optarg); break;
            case 'f': key_file = optarg; break;
            case 'p': peer_hex = optarg; break;
            case 'a': app_arg = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default:  print_usage(argv[0]); return 1;
        }
    }

    curl_global_init(CURL_GLOBAL_ALL);

    AppState st;
    memset(&st, 0, sizeof(st));
    st.kind     = kind;
    st.sockfd   = CURL_SOCKET_BAD;
    st.running  = true;
    if (app_arg) {
        strncpy(st.app_tag, app_arg, sizeof(st.app_tag) - 1);
    }

    strncpy(st.relay_url, relay_url, sizeof(st.relay_url) - 1);

    st.secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!st.secp_ctx) {
        fprintf(stderr, "secp256k1 初始化失败\n");
        curl_global_cleanup();
        return 1;
    }

    if (load_key(key_file, st.pubkey_hex, st.seckey) == 0) {
        if (!secp256k1_keypair_create(st.secp_ctx, &st.keypair, st.seckey)) {
            fprintf(stderr, "密钥文件损坏\n");
            secp256k1_context_destroy(st.secp_ctx);
            curl_global_cleanup();
            return 1;
        }
        printf("已加载密钥文件 %s\n", key_file);
    } else {
        if (gen_keypair(&st) != 0) {
            fprintf(stderr, "生成密钥失败\n");
            secp256k1_context_destroy(st.secp_ctx);
            curl_global_cleanup();
            return 1;
        }
        save_key(key_file, st.pubkey_hex, st.seckey);
        printf("已生成新密钥，保存到 %s\n", key_file);
    }

    {
        char display[KEY_HEX_LEN + 1];
        strcpy(display, st.pubkey_hex);
        str_to_upper(display);
        printf("我的公钥: %s\n", display);
    }

    if (peer_hex) {
        size_t plen = strlen(peer_hex);
        if (plen != KEY_HEX_LEN) {
            fprintf(stderr, "对端公钥长度应为 %d hex 字符\n", KEY_HEX_LEN);
            secp256k1_context_destroy(st.secp_ctx);
            curl_global_cleanup();
            return 1;
        }
        strncpy(st.peer_hex, peer_hex, KEY_HEX_LEN);
        st.peer_hex[KEY_HEX_LEN] = '\0';
        st.have_peer = true;
        // store lowercase for protocol, uppercase for display
        for (char *p = st.peer_hex; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        char d[KEY_HEX_LEN + 1];
        strcpy(d, st.peer_hex);
        str_to_upper(d);
        printf("对端公钥: %s\n", d);
    }

    st.curl = curl_easy_init();
    if (!st.curl) {
        fprintf(stderr, "curl 初始化失败\n");
        secp256k1_context_destroy(st.secp_ctx);
        curl_global_cleanup();
        return 1;
    }

    printf("正在连接 %s ...\n", st.relay_url);
    fflush(stdout);

    if (ws_connect(&st) != 0) {
        curl_easy_cleanup(st.curl);
        secp256k1_context_destroy(st.secp_ctx);
        curl_global_cleanup();
        return 1;
    }

    printf("已连接 %s\nkind=%d\n", st.relay_url, st.kind);
    fflush(stdout);

    chat_loop(&st);

    curl_easy_cleanup(st.curl);
    secp256k1_context_destroy(st.secp_ctx);
    curl_global_cleanup();
    return 0;
}
