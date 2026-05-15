#ifndef KEYRING_H
#define KEYRING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#define KEYRING_SEED_BYTES 48
#define KEYRING_KEY_BYTES  32

typedef struct {
    uint8_t seed[KEYRING_SEED_BYTES];
} KeyRing;

int  keyring_hex_to_bin(const char *hex, uint8_t *bin, size_t max_len);

void keyring_generate(KeyRing *kr);
int  keyring_load(const char *path, KeyRing *kr);
int  keyring_save(const char *path, const KeyRing *kr);

void keyring_nostr(const KeyRing *kr, secp256k1_context *ctx,
                   secp256k1_keypair *kp, uint8_t pub[KEYRING_KEY_BYTES]);

void keyring_btdht(const KeyRing *kr,
                   uint8_t seed_out[KEYRING_KEY_BYTES],
                   uint8_t pub[KEYRING_KEY_BYTES]);

EVP_PKEY *keyring_opendht(const KeyRing *kr);

void keyring_tox(const KeyRing *kr,
                 uint8_t sk[KEYRING_KEY_BYTES],
                 uint8_t pk[KEYRING_KEY_BYTES]);

EVP_PKEY *keyring_i2pd_ed(const KeyRing *kr);
EVP_PKEY *keyring_i2pd_x(const KeyRing *kr);

// ---- Ed25519 helpers ----
void keyring_ed25519_pub(const KeyRing *kr, uint8_t pub[KEYRING_KEY_BYTES]);

// ---- Group A: Ed25519 protocols ----
void keyring_torv3_onion(const KeyRing *kr, char *out, size_t out_len);
void keyring_torv3_secret(const KeyRing *kr, uint8_t *out);
void keyring_ssb_feedid(const KeyRing *kr, char *out, size_t out_len);
void keyring_hypercore_dk256(const KeyRing *kr, uint8_t out[32]);
void keyring_hypercore_dk512(const KeyRing *kr, uint8_t out[64]);
void keyring_cjdns_ipv6(const KeyRing *kr, char *out, size_t out_len);
void keyring_yggdrasil_ipv6(const KeyRing *kr, char *out, size_t out_len);
void keyring_nkn_nodeid(const KeyRing *kr, char *out, size_t out_len);
void keyring_gnunet_peerid(const KeyRing *kr, char *out, size_t out_len);
void keyring_bitcoin_tor_key(const KeyRing *kr, uint8_t *out);
void keyring_sia_nodekey(const KeyRing *kr, char *out, size_t out_len);
void keyring_tahoe_nodeid(const KeyRing *kr, char *out, size_t out_len);
void keyring_tribler_peerid(const KeyRing *kr, char *out, size_t out_len);
void keyring_stellar_nodeid(const KeyRing *kr, char *out, size_t out_len);
void keyring_handshake_nodekey(const KeyRing *kr, uint8_t *out);
void keyring_oxen_service_nodekey(const KeyRing *kr, uint8_t *out);
void keyring_kayaknet_nodeid(const KeyRing *kr, char *out, size_t out_len);
void keyring_cardano_kes_key(const KeyRing *kr, uint8_t *out);
void keyring_cardano_vrf_key(const KeyRing *kr, uint8_t *out);
void keyring_urbit_net_key(const KeyRing *kr, uint8_t *out);
void keyring_urbit_crypt_key(const KeyRing *kr, uint8_t *out);
void keyring_tailscale_node_key(const KeyRing *kr, uint8_t *out);
void keyring_tailscale_machine_key(const KeyRing *kr, uint8_t *out);
void keyring_tailscale_tlk(const KeyRing *kr, uint8_t *out);

// ---- Group B: secp256k1 protocols ----
void keyring_bitcoin_v2_key(const KeyRing *kr, uint8_t *out);
void keyring_eth_nodekey_hex(const KeyRing *kr, char *out, size_t out_len);
void keyring_eth_nodeid(const KeyRing *kr, char *out, size_t out_len);
int  keyring_eth_enr_nodeid(const KeyRing *kr, uint8_t out[32]);
void keyring_lightning_nodeid(const KeyRing *kr, char *out, size_t out_len);
void keyring_bitmessage_address(const KeyRing *kr, char *out, size_t out_len);
void keyring_zeronet_address(const KeyRing *kr, char *out, size_t out_len);
void keyring_avalanche_nodeid(const KeyRing *kr, char *out, size_t out_len);

// ---- Group C: RSA protocols ----
int  keyring_arweave_address(const KeyRing *kr, char *out, size_t out_len);
void keyring_storj_identity(const KeyRing *kr, char *out, size_t out_len);

// ---- Group D: BLS12-381 protocols ----
void keyring_chia_farmer_key(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48]);
void keyring_eth2_validator_key(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48]);
void keyring_avalanche_bls_key(const KeyRing *kr, uint8_t sk[32], uint8_t pk[48]);

// ---- Group E: libp2p ----
void keyring_libp2p_peerid(const KeyRing *kr, int kind, char *out, size_t out_len);

#endif
