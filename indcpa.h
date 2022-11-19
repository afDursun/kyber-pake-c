#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES

void encode_c0(unsigned char *r, const unsigned char *m, const unsigned char *seed, const unsigned char *cid);

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],polyvec *gamma,
                    const unsigned char *pw,
                    unsigned char *state,
                    const unsigned char *cid, 
                    const unsigned char *sid,
                    unsigned char *send);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

void hash_pw(poly *r, const unsigned char *seed, unsigned char nonce);
void hash_vec_frompw(polyvec *gamma, const unsigned char *pw, unsigned char nonce);
void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],polyvec *pk, const uint8_t seed[KYBER_SYMBYTES]);
void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk);

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)
#endif
