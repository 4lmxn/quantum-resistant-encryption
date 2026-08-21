#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "d_api.h"
static int h2b(const char*h,uint8_t*b,size_t n){for(size_t i=0;i<n;i++){unsigned v;if(sscanf(h+2*i,"%2x",&v)!=1)return -1;b[i]=v;}return 0;}
static void ph(const uint8_t*b,size_t n){for(size_t i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(int argc,char**argv){
  if(argc>=4 && !strcmp(argv[1],"sign")){
    uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES];
    size_t mlen=strlen(argv[3])/2; uint8_t*m=malloc(mlen);
    uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES]; size_t sl;
    if(h2b(argv[2],sk,sizeof(sk))||h2b(argv[3],m,mlen)){fprintf(stderr,"hex\n");return 1;}
    if(PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig,&sl,m,mlen,sk)){fprintf(stderr,"sign\n");return 1;}
    ph(sig,sl); return 0;
  }
  if(argc>=5 && !strcmp(argv[1],"verify")){
    uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
    size_t mlen=strlen(argv[3])/2; uint8_t*m=malloc(mlen);
    size_t sl=strlen(argv[4])/2; uint8_t*sig=malloc(sl);
    if(h2b(argv[2],pk,sizeof(pk))||h2b(argv[3],m,mlen)||h2b(argv[4],sig,sl)){fprintf(stderr,"hex\n");return 1;}
    int ok=PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig,sl,m,mlen,pk);
    printf("%s\n", ok==0?"OK":"FAIL"); return 0;
  }
  fprintf(stderr,"usage: sign sk msg | verify pk msg sig\n"); return 1;
}
