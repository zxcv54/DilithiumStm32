#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <stdio.h>
#include "api.h"
#include "rng.h"


#define TEST_ITERATIONS 5000
#define MSG_LEN 32

/* 返回结果统计 */
typedef struct {
    uint32_t keygen_success;
    uint32_t keygen_fail;
    uint32_t sign_success;
    uint32_t sign_fail;
    uint32_t verify_success;
    uint32_t verify_fail;
} test_result_t;

/*
 * 功能：
 *   每轮执行：
 *     1. 随机生成消息
 *     2. 重新生成密钥对
 *     3. 对消息签名
 * 
 *     4. 验签并检查恢复消息
 *
 * 返回值：
 *   0  : 整个流程执行完成
 *  <0 : 输入参数错误
 */

int run_random_keygen_sign_verify_5000(test_result_t *result)
{
    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t msg[MSG_LEN];
    static uint8_t sm[CRYPTO_BYTES + MSG_LEN];
    static uint8_t recovered[MSG_LEN];

    uint8_t entropy_input[48];
    unsigned long long smlen = 0;
    unsigned long long recovered_len = 0;
    uint32_t i;
    int ret;

    if (result == NULL) {
        return -1;
    }

    /* 清零统计结果 */
    result->keygen_success = 0;
    result->keygen_fail = 0;
    result->sign_success = 0;
    result->sign_fail = 0;
    result->verify_success = 0;
    result->verify_fail = 0;

    /*
     * 初始化随机数发生器
     * 这里使用固定熵输入，是为了让整次实验“可复现”：
     * 同样的程序、同样的实现、同样的初始状态下，
     * 5000 轮生成的随机序列是一致的。
     */
    for (i = 0; i < 48; i++) {
        entropy_input[i] = (uint8_t)i;
    }
    randombytes_init(entropy_input, NULL, 256);

    for (i = 0; i < TEST_ITERATIONS; i++) {
        /* 每轮随机生成消息 */
        randombytes(msg, MSG_LEN);

        /* 每轮重新生成密钥对 */
        ret = crypto_sign_keypair(pk, sk);
        if (ret != 0) {
            result->keygen_fail++;
            continue;
        }
        result->keygen_success++;

        /* 每轮签名 */
        ret = crypto_sign(sm, &smlen, msg, MSG_LEN, sk);
        if (ret != 0) {
            result->sign_fail++;
            continue;
        }
        result->sign_success++;

        /* 每轮验签 */
        ret = crypto_sign_open(recovered, &recovered_len, sm, smlen, pk);
        if (ret != 0) {
            result->verify_fail++;
            continue;
        }

        if (recovered_len != MSG_LEN) {
            result->verify_fail++;
            continue;
        }

        if (memcmp(msg, recovered, MSG_LEN) != 0) {
            result->verify_fail++;
            continue;
        }

        result->verify_success++;
    }

    return 0;
}



 int main(void)
{
    test_result_t result;
    int ret;

    ret = run_random_keygen_sign_verify_5000(&result);

    printf("ret = %d\n", ret);
    printf("keygen_success = %u\n", result.keygen_success);
    printf("keygen_fail    = %u\n", result.keygen_fail);
    printf("sign_success   = %u\n", result.sign_success);
    printf("sign_fail      = %u\n", result.sign_fail);
    printf("verify_success = %u\n", result.verify_success);
    printf("verify_fail    = %u\n", result.verify_fail);

    return 0;
}