#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"

#if defined(STM32F4xx) || defined(STM32F407xx) || defined(STM32F4xx_HAL_H)
#include "stm32f4xx_hal.h"
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <errno.h>
#ifdef __linux__
#include <unistd.h>
#include <sys/syscall.h>
#else
#include <unistd.h>
#endif
#endif

#if defined(STM32F4xx) || defined(STM32F407xx) || defined(STM32F4xx_HAL_H)
extern RNG_HandleTypeDef hrng;

void randombytes(uint8_t *out, size_t outlen) {
  uint32_t random_word = 0;
  size_t idx = 0;
  HAL_StatusTypeDef status;

  while(idx < outlen) {
    status = HAL_RNG_GenerateRandomNumber(&hrng, &random_word);
    if(status != HAL_OK) {
      while(1) {
      }
    }

    out[idx++] = (uint8_t)(random_word & 0xFFu);
    if(idx < outlen) out[idx++] = (uint8_t)((random_word >> 8) & 0xFFu);
    if(idx < outlen) out[idx++] = (uint8_t)((random_word >> 16) & 0xFFu);
    if(idx < outlen) out[idx++] = (uint8_t)((random_word >> 24) & 0xFFu);
  }
}
#elif defined(_WIN32)
void randombytes(uint8_t *out, size_t outlen) {
  HCRYPTPROV ctx;
  DWORD len;

  if(!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    abort();

  while(outlen > 0) {
    len = (outlen > 1048576) ? 1048576 : outlen;
    if(!CryptGenRandom(ctx, len, (BYTE *)out))
      abort();

    out += len;
    outlen -= len;
  }

  if(!CryptReleaseContext(ctx, 0))
    abort();
}
#elif defined(__linux__) && defined(SYS_getrandom)
void randombytes(uint8_t *out, size_t outlen) {
  ssize_t ret;

  while(outlen > 0) {
    ret = syscall(SYS_getrandom, out, outlen, 0);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#else
void randombytes(uint8_t *out, size_t outlen) {
  static int fd = -1;
  ssize_t ret;

  while(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1 && errno == EINTR)
      continue;
    else if(fd == -1)
      abort();
  }

  while(outlen > 0) {
    ret = read(fd, out, outlen);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#endif
