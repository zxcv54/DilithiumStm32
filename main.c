#include "test_sign.h"

volatile int g_ret;
volatile test_result_t g_result;

int main(void)
{
    g_ret = run_random_keygen_sign_5000((test_result_t *)&g_result);

    while (1) {
    }
}