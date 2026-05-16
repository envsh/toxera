//go:build ignore

#include "keyring.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static void print_label(const char *label) { printf("%-28s", label); }
static void print_hex(const uint8_t *data, size_t len) { for (size_t i = 0; i < len; i++) printf("%02X", data[i]); }
static void print_str(const char *s) { printf("%s", s); }

static void print_evp_pubkey(EVP_PKEY *pkey)
{
    if (!pkey) { printf("(null)\n"); return; }
    if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519 || EVP_PKEY_id(pkey) == EVP_PKEY_X25519) {
        uint8_t buf[32]; size_t len = 32;
        EVP_PKEY_get_raw_public_key(pkey, buf, &len);
        print_hex(buf, 32);
    } else if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        printf("RSA-%d bits", EVP_PKEY_get_bits(pkey));
    }
    printf("\n");
}

int main(void)
{
    KeyRing kr;
    const char *seed =
        "aabbccddee00112233445566778899aabbccddee00112233445566778899"
        "aabbccddee00112233445566778899aa";
    keyring_hex_to_bin(seed, kr.seed, KEYRING_SEED_BYTES);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    printf("=== Base protocols (existing) ===\n");
    {
        secp256k1_keypair kp; uint8_t pub[32];
        keyring_nostr(&kr, ctx, &kp, pub);
        print_label("Nostr (secp256k1):"); print_hex(pub, 32); printf("\n");
    }
    {
        uint8_t seed_out[32], pub[32];
        keyring_btdht(&kr, seed_out, pub);
        print_label("BT-DHT (ed25519):"); print_hex(pub, 32); printf("\n");
    }
    {
        EVP_PKEY *rsa = keyring_opendht(&kr);
        print_label("OpenDHT (RSA-4096):"); print_evp_pubkey(rsa); EVP_PKEY_free(rsa);
    }
    {
        uint8_t sk[32], pk[32];
        keyring_tox(&kr, sk, pk);
        print_label("Tox (X25519):"); print_hex(pk, 32); printf("\n");
        print_label("  clamped sk:"); print_hex(sk, 32); printf("\n");
    }
    {
        EVP_PKEY *ed = keyring_i2pd_ed(&kr);
        EVP_PKEY *x = keyring_i2pd_x(&kr);
        print_label("I2PD (Ed25519):"); print_evp_pubkey(ed);
        print_label("I2PD (X25519):"); print_evp_pubkey(x);
        EVP_PKEY_free(ed); EVP_PKEY_free(x);
    }

    printf("\n=== Group A: Ed25519 Protocols ===\n");
    {
        char buf[128];
        keyring_torv3_onion(&kr, buf, sizeof(buf));
        print_label("Tor V3 Onion:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_ssb_feedid(&kr, buf, sizeof(buf));
        print_label("SSB FeedID:"); print_str(buf); printf("\n");
    }
    {
        uint8_t dk[32]; keyring_hypercore_dk256(&kr, dk);
        print_label("Hypercore DK256:"); print_hex(dk, 32); printf("\n");
    }
    {
        uint8_t dk[64]; keyring_hypercore_dk512(&kr, dk);
        print_label("Hypercore DK512:"); print_hex(dk, 64); printf("\n");
    }
    {
        char buf[64];
        keyring_cjdns_ipv6(&kr, buf, sizeof(buf));
        print_label("Cjdns IPv6:"); print_str(buf); printf("\n");
    }
    {
        char buf[64];
        keyring_yggdrasil_ipv6(&kr, buf, sizeof(buf));
        print_label("Yggdrasil IPv6:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_nkn_nodeid(&kr, buf, sizeof(buf));
        print_label("NKN NodeID:"); print_str(buf); printf("\n");
    }
    {
        char buf[256];
        keyring_gnunet_peerid(&kr, buf, sizeof(buf));
        print_label("GNUnet PeerID:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_sia_nodekey(&kr, buf, sizeof(buf));
        print_label("Sia NodeKey:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_tahoe_nodeid(&kr, buf, sizeof(buf));
        print_label("Tahoe NodeID:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_tribler_peerid(&kr, buf, sizeof(buf));
        print_label("Tribler PeerID:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_stellar_nodeid(&kr, buf, sizeof(buf));
        print_label("Stellar NodeID:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_kayaknet_nodeid(&kr, buf, sizeof(buf));
        print_label("KayakNet NodeID:"); print_str(buf); printf("\n");
    }

    printf("\n=== Group B: secp256k1 Protocols ===\n");
    {
        char buf[256];
        keyring_eth_nodekey_hex(&kr, buf, sizeof(buf));
        print_label("Ethereum NodeKey:"); print_str(buf); printf("\n");
    }
    {
        char buf[256];
        keyring_eth_nodeid(&kr, buf, sizeof(buf));
        print_label("Ethereum NodeID:"); print_str(buf); printf("\n");
    }
    {
        uint8_t enr[32];
        keyring_eth_enr_nodeid(&kr, enr);
        print_label("Ethereum ENR ID:"); print_hex(enr, 32); printf("\n");
    }
    {
        char buf[256];
        keyring_lightning_nodeid(&kr, buf, sizeof(buf));
        print_label("Lightning NodeID:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_bitmessage_address(&kr, buf, sizeof(buf));
        print_label("Bitmessage:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_zeronet_address(&kr, buf, sizeof(buf));
        print_label("ZeroNet:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_avalanche_nodeid(&kr, buf, sizeof(buf));
        print_label("Avalanche NodeID:"); print_str(buf); printf("\n");
    }

    printf("\n=== Group C: RSA Protocols ===\n");
    {
        char buf[128];
        keyring_arweave_address(&kr, buf, sizeof(buf));
        print_label("Arweave:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_storj_identity(&kr, buf, sizeof(buf));
        print_label("Storj ID:"); print_str(buf); printf("\n");
    }

    printf("\n=== Group D: BLS12-381 Protocols ===\n");
    {
        uint8_t sk[32], pk[48];
        keyring_chia_farmer_key(&kr, sk, pk);
        print_label("Chia Farmer PK:"); print_hex(pk, 48); printf("\n");
    }
    {
        uint8_t sk[32], pk[48];
        keyring_eth2_validator_key(&kr, sk, pk);
        print_label("ETH2 Validator PK:"); print_hex(pk, 48); printf("\n");
    }
    {
        uint8_t sk[32], pk[48];
        keyring_avalanche_bls_key(&kr, sk, pk);
        print_label("Avalanche BLS PK:"); print_hex(pk, 48); printf("\n");
    }

    printf("\n=== Group E: libp2p ===\n");
    {
        char buf[128];
        keyring_libp2p_peerid(&kr, 0, buf, sizeof(buf));
        print_label("libp2p Ed25519:"); print_str(buf); printf("\n");
    }
    {
        char buf[128];
        keyring_libp2p_peerid(&kr, 1, buf, sizeof(buf));
        print_label("libp2p Secp256k1:"); print_str(buf); printf("\n");
    }
    {
        char buf[256];
        keyring_libp2p_peerid(&kr, 2, buf, sizeof(buf));
        print_label("libp2p RSA:"); print_str(buf); printf("\n");
    }

    secp256k1_context_destroy(ctx);
    return 0;
}
