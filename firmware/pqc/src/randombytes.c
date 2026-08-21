#include "randombytes.h"
#if defined(ESP32) || defined(ARDUINO)
#include "esp_random.h"
int randombytes(uint8_t *out, size_t n){
  // esp_random() is the ESP32 hardware RNG (true entropy once RF is up).
  for(size_t i=0;i<n;i+=4){uint32_t r=esp_random();size_t k=(n-i<4)?n-i:4;
    for(size_t j=0;j<k;j++)out[i+j]=(r>>(8*j))&0xff;}
  return 0;
}
#else
#include <stdio.h>
int randombytes(uint8_t *out, size_t n){FILE*f=fopen("/dev/urandom","rb");if(!f)return -1;size_t r=fread(out,1,n,f);fclose(f);return r==n?0:-1;}
#endif
