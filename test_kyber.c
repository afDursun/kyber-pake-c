#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kyber-pake.h"
#include "randombytes.h"
#include "polyvec.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed_print.h"

#define NTESTS 1

static int test_keys()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  int i = 0;
  uint8_t pw[PW_BYTES];
  uint8_t cid[ID_BYTES];
  uint8_t sid[ID_BYTES];

  uint8_t k_prime[PAKE_VERIFY];
  uint8_t session_key_c[SESSION_KEY];
  uint8_t session_key_s[SESSION_KEY];


  for(i = 0 ; i < ID_BYTES ; i++){
    pw[i] = 1;
    cid[i] = 2;
    sid[i] = 3;
  }

  polyvec gamma;
  uint8_t state_1[HASH_BYTES+3] ={0};
  uint8_t state_2[HASH_BYTES+3] = {0};
  uint8_t send_c0[PAKE_SENDC0];
  uint8_t send_s0[PAKE_SENDS0];



  pake_c0(pk, sk,pw,state_1,cid,sid,send_c0,&gamma);

  pake_s0(send_s0, send_c0, &gamma, sid, state_2,ct,key_a);

  pake_c1(session_key_c, k_prime, send_s0, sk , pk , state_1);

  pake_s1(session_key_s, k_prime, state_2);


  printf("**********************\nSession Key Client : ");
  for(i = 0 ; i < SESSION_KEY ; i++){
    printf("%02x", session_key_c[i]);
  }

  printf("\nSession Key Server : ");
  for(i = 0 ; i < SESSION_KEY ; i++){
    printf("%02x", session_key_s[i]);
  }

  printf("\n**********************");
  return 0;
}





int main(void)
{
  

  int r;
  r  = test_keys();
  
  /*for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk_a();
    r |= test_invalid_ciphertext();
    if(r)
      return 1;
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);
*/
  return 0;
}
