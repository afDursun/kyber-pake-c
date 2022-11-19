#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "kyber-pake.h"
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed_print.h"
#include <sys/time.h>

#define NTESTS 1000

uint64_t t[NTESTS];

uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t sk[CRYPTO_SECRETKEYBYTES];
uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

uint8_t seed[KYBER_SYMBYTES] = {0};
uint8_t pw[32] = {0};
uint8_t cid[32] = {0};
uint8_t sid[32] = {0};
uint8_t state_1[HASH_BYTES+3] ={0};
uint8_t state_2[HASH_BYTES+3] = {0};
uint8_t send_c0[PAKE_SENDC0];
uint8_t send_s0[PAKE_SENDS0];
uint8_t key_a[CRYPTO_BYTES];
uint8_t k_prime[PAKE_VERIFY];
uint8_t session_key_c[SESSION_KEY];
uint8_t session_key_s[SESSION_KEY];

int main()
{
  unsigned int i;
  
  struct timeval timeval_start, timeval_end;
  polyvec gamma;
  printf("\n--------------------\n");
  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_c0(pk, sk,pw,state_1,cid,sid,send_c0,&gamma);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of c0:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));

  //print_results("pake_c0: ", t, NTESTS);


  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_s0(send_s0, send_c0, &gamma, sid, state_2,ct,key_a);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of s0:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));

  //print_results("pake_s0: ", t, NTESTS);

  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_c1(session_key_c, k_prime, send_s0, sk , pk , state_1);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of c1:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));

  //print_results("pake_c1: ", t, NTESTS);

  gettimeofday(&timeval_start, NULL);
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    pake_s1(session_key_s, k_prime, state_2);
  }
  gettimeofday(&timeval_end, NULL);
  printf("The average time of s1:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (NTESTS * 1.0));
printf("\n--------------------\n");
  //print_results("pake_s1: ", t, NTESTS);

  



  return 0;
}
