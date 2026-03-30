#ifndef TEST_SIGN_H
#define TEST_SIGN_H

#include <stdint.h>

typedef struct {
    uint32_t keygen_success;
    uint32_t keygen_fail;
    uint32_t sign_success;
    uint32_t sign_fail;
} test_result_t;

int run_random_keygen_sign_5000(test_result_t *result);

#endif