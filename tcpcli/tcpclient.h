

// struct TcpNode
// struct TcpPeerConn
// TcpNode* TcpNode_new(keyfile)
// connect(ip,port,pubkey) // relay
// TcpNode_send(peer,data)
// TcpPeerConn* TcpNode_connect_peer(pubkey)
// TcpPeerconn_send(data)

// libtoxcore.so protected funcs

#ifndef TCP_CLIENT_INNER_H
#define TCP_CLIENT_INNER_H

#include <stdint.h>

#define TOX_KEY_SIZE 32
#define TOX_PACKET_SIZE 1372

// utils
extern void* os_memory();
extern void* os_random();
extern void* os_network();
extern void* logger_new(void* mem);
extern void* mono_time_new(void* mem, void*, void*);
extern void* netprof_new(void* logger, void* mem);

// connections
// self, relay, peer

// proxy_info cannot nil, zero ok
extern void* new_tcp_connections(void* logger, void* mem,
				 void* rng, void* network,
				 void* mono_time, void* self_sk,
				 void* proxy_info, void* netprof);
extern void do_tcp_connections(void* logger, void* tcp_c, void* userdata);
extern void kill_tcp_connections(void* tcp_c);

// return ?
extern int add_tcp_relay_global(void* tcp_c, void* ip_port, void* relay_pk);
extern bool tcp_relay_is_valid(void* tcp_c, void* relay_pk);
extern int tcp_connected_relays_count(void* tcp_c);
extern int find_tcp_connection_relay(void* tcp_c, void* relay_pk);
extern int tcp_connections_count(void* tcp_c);
extern int set_tcp_onion_status(void* tcp_c, bool enabled);

// return conn_num or -1
// id callback value
extern int new_tcp_connection_to(void* tcp_c, void* peer_pk, int id);
extern int kill_tcp_connection_to(void* tcp_c, int conn_num);

// send packet to peer over any relay
extern int send_packet_tcp_connection(void* tcp_c, int conn_num, void* pkt, short len);

extern int tcp_send_onion_request(void* tcp_c, int conn_num, void* data, short len);

// send like udp, don't known when send fail
extern int tcp_send_oob_packet_using_relay(void* tcp_c, void* relay_pk, void* peer_pk, void* data, short len);

// object is registered
// userdata is iterated
// on_oob_packet(void* object, uint8_t * public_key, int tcp_connections_number, uint8_t * packet, uint16_t length, void* userdata)
extern void set_oob_packet_tcp_connection_callback(void* tcp_c,
						   void* cbfn,
						   void* object);
// on_data_packet(void *object, int crypt_connection_id, const uint8_t * packet, uint16_t length, void *cbval)
extern void set_packet_tcp_connection_callback(void* tcp_c,
					       void* cbfn,
					       void* object);

// todo forward/onion packet callback


extern void logger_callback_log(void* logger, void* logcb, void* a, void* b);

/////
typedef struct Family {
    uint8_t value;
} Family;

typedef union IP4 {
    uint32_t uint32;
    uint16_t uint16[2];
    uint8_t uint8[4];
} IP4;

typedef union IP6 {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    uint64_t uint64[2];
} IP6;

typedef union IP_Union {
    IP4 v4;
    IP6 v6;
} IP_Union;

typedef struct IP {
    Family family;
    IP_Union ip;
} IP;

typedef struct IP_Port {
    IP ip;
    uint16_t port;
} IP_Port;

extern Family net_family_ipv4();
extern uint16_t net_htons(uint16_t);
// 1 ok, 0 fail
extern bool addr_parse_ip(const char* ipstr, IP* ipbin);

/////
extern void crypto_new_keypair(void* rng, void* pk, void* sk);

///// cliutils.c
extern int toxin_save_keys(void* path, void* pk, void* sk);
extern int toxin_load_keys(void* path, void* pk, void* sk);
// extern int toxin_save_keys(const char *path, const uint8_t *pk, const uint8_t *sk);
// extern int toxin_load_keys(const char *path, uint8_t *pk, uint8_t *sk);

#endif // TCP_CLIENT_INNER_H
