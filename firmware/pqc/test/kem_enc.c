#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
static int hex2bin(const char*h,uint8_t*b,size_t n){for(size_t i=0;i<n;i++){unsigned v;if(sscanf(h+2*i,"%2x",&v)!=1)return -1;b[i]=v;}return 0;}
static void phex(const uint8_t*b,size_t n){for(size_t i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: enc <pk_hex>\n");return 1;}
  uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
  uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
  if(hex2bin(argv[1],pk,sizeof(pk))){fprintf(stderr,"bad pk hex\n");return 1;}
  if(PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct,ss,pk)){fprintf(stderr,"enc failed\n");return 1;}
  phex(ct,sizeof(ct)); phex(ss,sizeof(ss));
  return 0;
}
