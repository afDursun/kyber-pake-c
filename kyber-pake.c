#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "kyber-pake.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"
#include "poly.h"
#include "polyvec.h"

void encode_c0(unsigned char *r, const unsigned char *m, const unsigned char *seed, const unsigned char *cid)
{
    int i;


    for ( i = 0; i < KYBER_POLYVECBYTES; i++)
        r[i] = m[i];

    for ( i = 0; i < SEED_BYTES; i++)
        r[i + KYBER_POLYVECBYTES ] = seed[i];

    for ( i = 0; i < ID_BYTES; i++)
        r[KYBER_POLYVECBYTES + SEED_BYTES + i] = cid[i];

}

void decode_c0(polyvec *m, unsigned char *seed, unsigned char *cid, const unsigned char *r)
{
    int i;
    polyvec_frombytes(m, r);
    for(i = 0; i<SEED_BYTES; i++)
        seed[i] = r[i + KYBER_POLYVECBYTES];
    for(i = 0; i<ID_BYTES;i++)
        cid[i] = r[i + KYBER_POLYVECBYTES + SEED_BYTES];

}
void encode_s0(unsigned char *r, const unsigned char *y_c, const unsigned char *c,const unsigned char *k)
{ //send yc ct k
    int i;

    for(i = 0; i< KYBER_POLYVECBYTES; i++)
        r[i] = y_c[i];
    for(i = 0 ; i < CRYPTO_CIPHERTEXTBYTES ; i++)
        r[i+KYBER_POLYVECBYTES] = c[i];

    for(i = 0; i< ID_BYTES; i++)
        r[i + KYBER_POLYVECBYTES + CRYPTO_CIPHERTEXTBYTES] =  k[i];
}
void decode_s0(uint8_t *yc_bytes, uint8_t *c, unsigned char *k, const unsigned char *r)
{
  int i;

  for(i = 0; i< KYBER_POLYVECBYTES;i++)
      yc_bytes[i] = r[i];

  for(i = 0; i< CRYPTO_CIPHERTEXTBYTES;i++)
    c[i] = r[i  + KYBER_POLYVECBYTES];


  for(i = 0; i< PAKE_VERIFY;i++)
    k[i] = r[i + KYBER_POLYVECBYTES + CRYPTO_CIPHERTEXTBYTES];
 
}

void hash_pw(poly *a, const unsigned char *seed, unsigned char nonce)
{
  unsigned int pos = 0, ctr = 0;
  uint16_t val;
  unsigned int nblocks=4;
  uint8_t buf[SHAKE128_RATE*nblocks];
  int i;
  unsigned char extseed[SEED_BYTES+1];

  keccak_state states;

  for(i=0;i<SEED_BYTES;i++){
    extseed[i] = seed[i];
  }

  extseed[SEED_BYTES] = nonce;


  shake128_absorb_once(&states,extseed,SEED_BYTES+1);
  shake128_squeezeblocks(buf,nblocks,&states);

  while(ctr < KYBER_N)
  {
    val = (buf[pos] | ((uint16_t) buf[pos+1] << 8)) & 0x1fff;
    if(val < KYBER_Q)
    {
        a->coeffs[ctr++] = val;
    }
    pos += 2;

    if(pos > SHAKE128_RATE*nblocks-2)
    {
      nblocks = 1;
      pos = 0;
    }
  }

}

void hash_vec_frompw(polyvec *gamma, const unsigned char *pw, unsigned char nonce)
{
  int i;
  for(i = 0; i< KYBER_K;i++)
  {
    hash_pw(gamma->vec+i, pw, nonce++);
  }
} 

void pake_c0(uint8_t *pk, uint8_t *sk, uint8_t *pw, uint8_t *state,uint8_t *cid, uint8_t *sid, uint8_t *send_a, polyvec *gamma)
{

  unsigned int i,j ;
  uint8_t buf[2*KYBER_SYMBYTES];
  uint8_t publicseed[KYBER_SYMBYTES];
  uint8_t noiseseed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv,m;

  randombytes(publicseed, KYBER_SYMBYTES);
  randombytes(noiseseed, KYBER_SYMBYTES);
  
  randombytes(buf, KYBER_SYMBYTES);
  hash_g(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  //polyvec_reduce(&pkpv);

  hash_vec_frompw(gamma, pw, nonce);
  polyvec_add(&m, &pkpv, gamma);

  

  for(i = 0; i< KYBER_K; i++)
        for (j = 0; j < KYBER_N; j++)
            gamma->vec[i].coeffs[j] = KYBER_Q - gamma->vec[i].coeffs[j];

  for (i = 0; i < ID_BYTES; i++)
  {
    state[i] = cid[i];
    state[i + ID_BYTES] = sid[i];
  }
  unsigned char mbytes[KYBER_POLYVECBYTES];
  unsigned char gammabytes[KYBER_POLYVECBYTES];

  polyvec_tobytes(mbytes, &m);


    for (i = 0; i < KYBER_POLYVECBYTES; i++)
        state[i+2*ID_BYTES] = mbytes[i];

  polyvec_tobytes(gammabytes, gamma);

    for (i = 0; i < KYBER_POLYVECBYTES; i++)
        state[i+2*ID_BYTES+KYBER_POLYVECBYTES] = gammabytes[i];

  encode_c0(send_a, mbytes, publicseed, cid);
    

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
}

void pake_s0(unsigned char *send, const unsigned char *received, const polyvec *gamma, const unsigned char *sid, unsigned char *state,uint8_t *ct, uint8_t *ss)
{
  uint8_t pk_s0[CRYPTO_PUBLICKEYBYTES];
  polyvec m;
  polyvec y_c;
  int i,j,counter = 0;
  unsigned char seed[SEED_BYTES];
  unsigned char cid[ID_BYTES];

  decode_c0(&m, seed, cid, received);

  //m'nin modQ da olduğunu kontrol et
  for (i = 0; i < KYBER_K; i++) {
    for (j = 0; j < KYBER_N ; j++) {
        if (m.vec[i].coeffs[j] > KYBER_Q) {
            counter++;
            printf("%d , %d  ,%u\n",i,j,m.vec[i].coeffs[j]);
         }
     }
  }

  if(counter==0){
      for(i = 0 ; i < KYBER_K ; i++){
        for(j = 0 ; j < KYBER_N ; j++){
        y_c.vec[i].coeffs[j] = (m.vec[i].coeffs[j] + gamma->vec[i].coeffs[j]) % KYBER_Q ; 
      }
    }
    pack_pk(pk_s0, &y_c, seed);
    crypto_kem_enc(ct,ss,pk_s0);

    for (i = 0; i < ID_BYTES; i++) {
        state[i] = cid[i];
        state[i + ID_BYTES] = sid[i];
    }

    unsigned char mbytes[KYBER_POLYVECBYTES];
    unsigned char gammabytes[KYBER_POLYVECBYTES];
    unsigned char yc_bytes[KYBER_POLYVECBYTES];

    polyvec_tobytes(mbytes, &m);


    for (i = 0; i < KYBER_POLYVECBYTES; i++)
        state[i+2*ID_BYTES] = mbytes[i];

    polyvec_tobytes(gammabytes, gamma);
    

    for (i = 0; i < KYBER_POLYVECBYTES; i++)
        state[i+2*ID_BYTES+KYBER_POLYVECBYTES] = gammabytes[i];


    polyvec_tobytes(yc_bytes, &y_c);

    for (i = 0; i < KYBER_POLYVECBYTES; i++)
        state[i+2*ID_BYTES+(2*KYBER_POLYVECBYTES)] = yc_bytes[i];

    for (i = 0; i < ID_BYTES; i++)
        state[i+2*ID_BYTES+(3*KYBER_POLYVECBYTES)] = ss[i];

    encode_s0(send, yc_bytes, ct ,ss);

  }
  else{
    printf("%s","S0 Abort-IF");
  }
}

void pake_c1(unsigned char *sharedkey_c, unsigned char *k_prime, const unsigned char *received, uint8_t *sk, uint8_t *pk ,unsigned char *state){
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t yc_bytes[KYBER_POLYVECBYTES];
  uint8_t decode_k[CRYPTO_BYTES];
  uint8_t decapsulation_k[CRYPTO_BYTES];
  polyvec p_key,p_key_c0;
  int i,j,counter=0;

  decode_s0(yc_bytes,ct,decode_k,received);
  polyvec_frombytes(&p_key,yc_bytes);
  polyvec_frombytes(&p_key_c0,pk);

  for (i = 0; i < KYBER_K; i++) {
    for (j = 0; j < KYBER_N; j++) {
      if (p_key_c0.vec[i].coeffs[j] != p_key.vec[i].coeffs[j]) {
          counter++;
      }
    }
  }
  //pk'ları karşılaştır. C0 da üretilen pk ve c1'e aktarılan pk
  if(counter==0){
    crypto_kem_dec(decapsulation_k,ct,sk);
    //Decapsulation ile elde edilen ve S0'da encapsualtion ile üretilen K ları karşılaştır
    if(memcmp(decapsulation_k, decode_k, 32) == 0){
      for (i = 0; i < KYBER_POLYVECBYTES; i++)
          state[i+2*ID_BYTES+(2*KYBER_POLYVECBYTES)] = yc_bytes[i];

      for (i = 0; i < ID_BYTES; i++)
          state[i+2*ID_BYTES+(3*KYBER_POLYVECBYTES)] = decapsulation_k[i];


      state[HASH_BYTES] = 0;
      shake256(k_prime, PAKE_VERIFY, state, HASH_BYTES+1);

      state[HASH_BYTES+1] = 1;
      shake256(sharedkey_c, SESSION_KEY, state, HASH_BYTES+2);
    }
    else{
      printf("%s\n", "C1 Abort-IF-k");
    }


  }
  else{
    printf("%s\n", "C1 Abort-IF");
  }

}

void pake_s1(unsigned char *sharedkey_s, const unsigned char *k_3_c, unsigned char *state)
{
  uint8_t k_2_prime[PAKE_VERIFY];
  shake256(k_2_prime, PAKE_VERIFY, state, HASH_BYTES+1);

  //s0 da üretilen K ve c1 den gelen k karşılaştır
  if(memcmp(k_2_prime, k_3_c, 32) == 0){
    state[HASH_BYTES+1]  = 1;
    shake256(sharedkey_s,SESSION_KEY, state, HASH_BYTES+2);  
  }
  else{
    printf("S1 Abort-IF");
  }
    
}


/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}
