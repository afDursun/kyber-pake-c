#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber512-90s"
#else
#define CRYPTO_ALGNAME "Kyber512"
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber768-90s"
#else
#define CRYPTO_ALGNAME "Kyber768"
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber1024-90s"
#else
#define CRYPTO_ALGNAME "Kyber1024"
#endif
#endif



void decode_c0(polyvec *m, unsigned char *seed, unsigned char *cid, const unsigned char *r);
void encode_s0(unsigned char *r, const unsigned char *y_c, const unsigned char *c,const unsigned char *k);
void decode_s0(uint8_t *yc_bytes, uint8_t *c, unsigned char *k, const unsigned char *r);



#define pake_c0 KYBER_NAMESPACE(keypair)
void pake_c0(uint8_t *pk, uint8_t *sk,uint8_t *pw,uint8_t *state,uint8_t *cid, uint8_t *sid, uint8_t *send,polyvec *gamma);
void pake_s0(unsigned char *send, const unsigned char *received, const polyvec *gamma, const unsigned char *sid, unsigned char *state,uint8_t *ct, uint8_t *ss);
void pake_c1(unsigned char *sharedkey_c, unsigned char *k_3_c, const unsigned char *received, uint8_t *sk, uint8_t *pk ,unsigned char *state);
void pake_s1(unsigned char *sharedkey_s, const unsigned char *k_3_c,unsigned char *state);	
	

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);



#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
