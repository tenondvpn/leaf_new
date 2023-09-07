#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "sm.h"
#include "include/tsm_err.h"
#include "../test_utils.h"

#define RET_OK    0
#define RET_ERR  (-1)

#define SM4_KEY_BYTE_LENGTH      16
#define SM4_IV_LENGTH      16

const unsigned char SM4_PLAIN[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                                     0x32, 0x10};
const unsigned char SM4_KEY[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                                   0x32, 0x10};
const unsigned char SM4_IV[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                                  0x32, 0x10};
const unsigned char SM4_ECB_CIPHER[16] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53,
                                          0x6e, 0x42, 0x46};
const unsigned char SM4_ECB_CIPHER_WITH_PADDING[32] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9,
                                                       0x4f, 0x53, 0x6e, 0x42, 0x46,
                                                       0x00, 0x2a, 0x8a, 0x4e, 0xfa, 0x86, 0x3c, 0xca, 0xd0, 0x24, 0xac,
                                                       0x03, 0x00, 0xbb, 0x40, 0xd2};
const unsigned char SM4_CBC_CIPHER[16] = {0x26, 0x77, 0xf4, 0x6b, 0x09, 0xc1, 0x22, 0xcc, 0x97, 0x55, 0x33, 0x10, 0x5b,
                                          0xd4, 0xa2, 0x2a};
const unsigned char SM4_CBC_CIPHER_WITH_PADDING[32] = {0x26, 0x77, 0xf4, 0x6b, 0x09, 0xc1, 0x22, 0xcc, 0x97, 0x55, 0x33,
                                                       0x10, 0x5b, 0xd4, 0xa2, 0x2a,
                                                       0x3b, 0x88, 0x0e, 0x68, 0x67, 0x77, 0x25, 0x22, 0xae, 0x55, 0xd2,
                                                       0xf0, 0xae, 0x74, 0x78, 0xae};
const unsigned char SM4_CTR_CIPHER[16] = {0x69, 0x3d, 0x9a, 0x53, 0x5b, 0xad, 0x5b, 0xb1, 0x78, 0x6f, 0x53, 0xd7, 0x25,
                                          0x3a, 0x70, 0x56};

/* SM4除ECB模式以外，其他模式的测试用例的加密长度需大于一个分组 */
#define SM4_GCM_TEST_PLAIN_LEN 64
#define SM4_GCM_TEST_CIPHER_LEN 80
#define SM4_GCM_TEST_CIPHER_NOPADDING_LEN 64
const unsigned char SM4_GCM_TEST_KEY[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                                            0x76, 0x54, 0x32, 0x10};
const unsigned char SM4_GCM_TEST_IV[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
                                           0x54, 0x32, 0x10};
const unsigned char SM4_GCM_TEST_PLAIN[64] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                                              0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                              0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
                                              0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                              0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                                              0x76, 0x54, 0x32, 0x10};
const unsigned char SM4_GCM_TEST_CIPHER[80] = {0x9C, 0x6C, 0xA8, 0xBC, 0x56, 0x78, 0x5E, 0xF6, 0x56, 0xDB, 0x0E, 0x1C,
                                               0xDB, 0xF9, 0x63, 0xFD, 0xE1, 0x41, 0xAB, 0x56, 0x17, 0xD2, 0xE1, 0xD7,
                                               0x95, 0x86, 0x70, 0x35, 0x3F, 0x37, 0x59, 0x82, 0xFF, 0xB1, 0xC8, 0x5F,
                                               0xAD, 0x11, 0x17, 0xC8, 0x48, 0xE2, 0x6D, 0x45, 0x7D, 0xF5, 0x77, 0xEC,
                                               0x82, 0xEB, 0xF9, 0x64, 0x55, 0xA7, 0xD0, 0x06, 0x70, 0xEA, 0xC1, 0x93,
                                               0x9D, 0xCF, 0x7F, 0xB8, 0x77, 0x36, 0x8F, 0xB2, 0xB3, 0x03, 0x47, 0x86,
                                               0x14, 0x0F, 0x58, 0x8B, 0x83, 0x69, 0x3F, 0x24};
const unsigned char SM4_GCM_TEST_CIPHER_NOPADDING[64] = {0x9C, 0x6C, 0xA8, 0xBC, 0x56, 0x78, 0x5E, 0xF6, 0x56, 0xDB,
                                                         0x0E, 0x1C, 0xDB, 0xF9, 0x63, 0xFD, 0xE1, 0x41, 0xAB, 0x56,
                                                         0x17, 0xD2, 0xE1, 0xD7, 0x95, 0x86, 0x70, 0x35, 0x3F, 0x37,
                                                         0x59, 0x82, 0xFF, 0xB1, 0xC8, 0x5F, 0xAD, 0x11, 0x17, 0xC8,
                                                         0x48, 0xE2, 0x6D, 0x45, 0x7D, 0xF5, 0x77, 0xEC, 0x82, 0xEB,
                                                         0xF9, 0x64, 0x55, 0xA7, 0xD0, 0x06, 0x70, 0xEA, 0xC1, 0x93,
                                                         0x9D, 0xCF, 0x7F, 0xB8};
const unsigned char SM4_GCM_TEST_AAD[16] = {0x26, 0x77, 0xF4, 0x6B, 0x09, 0xC1, 0x22, 0xCC, 0x97, 0x55, 0x33, 0x10,
                                            0x5B, 0xD4, 0xA2, 0x2A};
const unsigned char SM4_GCM_TEST_TAG[16] = {0xD5, 0x48, 0xE8, 0x4C, 0x7E, 0xB4, 0xB3, 0xAF, 0xC4, 0xC3, 0x87, 0x03,
                                            0x39, 0x99, 0x0D, 0xE1};
const unsigned char SM4_GCM_TEST_TAG_NOPADDING[16] = {0x52, 0x93, 0xFA, 0xA2, 0xE8, 0xC9, 0xA6, 0x7E, 0x77, 0xF8, 0x77,
                                                      0xC7, 0xAD, 0x34, 0x9D, 0x8C};


void random_content(size_t len, unsigned char *out) {

    for (size_t i = 0; i < len; ++i) {
        srand((unsigned int) time(NULL) + (unsigned int) i);
        out[i] = rand() % 256;
    }
}

unsigned long get_tick_count() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}


/**
 * 单元测试：CTR 加密与解密
 */
void test_sm4_generate_key(int times) {
    unsigned char key[SM4_KEY_BYTE_LENGTH] = {0};
    size_t key_len = 0;
    unsigned long cost_time = 0;
    for (int i = 0; i < times; i++) {
        unsigned long begin = get_tick_count();
        int ret = generate_symmetric_key(key, &key_len, SM4);
        if (ret != RESP_SMCRYPTO_OK) {
            fprintf(stdout, "SM4 generate key throws error.");
            break;
        }
        unsigned long end = get_tick_count();
        cost_time += end - begin;
    }

    float tps = (float) times / (cost_time / 1000.0);
    printf("SM4 generate key perf: [tps :%lu]\n", (long) tps);
}

/**
 * 单元测试：ECB 加密与解密
 */
int test_sm4_ecb_encrypt_decrypt(int times, size_t data_length) {
    int ret = RET_OK;
    size_t plain_len = data_length;
    unsigned char plain[plain_len];
    random_content(plain_len, plain);

    size_t cipher_len = plain_len + 16;
    unsigned char cipher[cipher_len];
    memset(cipher, 0x00, cipher_len);

    unsigned char out_plain[cipher_len];
    memset(out_plain, 0x00, cipher_len);
    size_t out_plain_len = cipher_len;

    int enc_ret = ecb_encrypt(plain, plain_len, cipher, &cipher_len,
                              SM4_KEY, 16, PADDING, SM4);
    fprintf(stdout, "cipher length: %zu", cipher_len);

    int dec_ret = ecb_decrypt(cipher, cipher_len, out_plain, &out_plain_len,
                              SM4_KEY, 16, PADDING, SM4);


    if (enc_ret != RESP_SMCRYPTO_OK || dec_ret != RESP_SMCRYPTO_OK ||
        out_plain_len != plain_len || memcmp(out_plain, plain, plain_len)) {
        fprintf(stdout, "SM4 ECB enc and dec throw error.");
        ret = RET_ERR;
    }

    return ret;
}


/**
 * 单元测试：CBC 加密与解密
 */
int test_sm4_cbc_encrypt_decrypt(int times, size_t data_length) {
    int ret = RET_OK;
    size_t plain_len = data_length;
    unsigned char plain[plain_len];
    random_content(plain_len, plain);

    size_t cipher_len = plain_len + 16;
    unsigned char cipher[cipher_len];
    memset(cipher, 0x00, cipher_len);

    unsigned char out_plain[cipher_len];
    memset(out_plain, 0x00, cipher_len);
    size_t out_plain_len = cipher_len;

    unsigned long encrypt_total_time = 0;
    unsigned long decrypt_total_time = 0;

    // 调用times次
    for (int i = 0; i < times; i++) {
        unsigned long encrypt_begin = get_tick_count();
        cbc_encrypt(plain, plain_len, cipher, &cipher_len,
                    SM4_KEY, 16,
                    SM4_IV, 16, PADDING, SM4);

        unsigned long encrypt_end_or_decrypt_begin = get_tick_count();
        encrypt_total_time += encrypt_end_or_decrypt_begin - encrypt_begin;

        cbc_decrypt(cipher, cipher_len, out_plain, &out_plain_len,
                    SM4_KEY, 16,
                    SM4_IV, 16, PADDING, SM4);

        unsigned long decrypt_end = get_tick_count();
        decrypt_total_time += decrypt_end - encrypt_end_or_decrypt_begin;

        if (out_plain_len != plain_len || memcmp(out_plain, plain, plain_len)) {
            fprintf(stdout, "SM4 CBC enc and dec throw error.");
            ret = RET_ERR;
            break;
        }
    }
    double encrypt_count_per_second = (float) times / (encrypt_total_time / 1000.0);
    double decrypt_count_per_second = (float) times / (decrypt_total_time / 1000.0);

    printf("SM4-CBC asymmetric_encrypt perf:[block size:%lu][tps :%lu][%lf MBps]\n",
           data_length, (long) encrypt_count_per_second, data_length * encrypt_count_per_second / 1024 / 1024);

    printf("SM4-CBC asymmetric_decrypt perf:[block size:%lu][tps :%lu][%lf MBps]\n",
           data_length, (long) decrypt_count_per_second, data_length * decrypt_count_per_second / 1024 / 1024);

    return ret;
}

/**
 * 单元测试：GCM 加密与解密
 */
void test_sm4_gcm_encrypt_decrypt(int times, size_t data_length) {
    int ret = RET_OK;
    size_t plainlen = data_length;
    unsigned char plain[plainlen];
    random_content(plainlen, plain);

    size_t cipherlen = plainlen + 16;
    unsigned char cipher[cipherlen];
    memset(cipher, 0x00, cipherlen);

    unsigned char tag[16] = {0};
    size_t taglen = 16;

    unsigned char outplain[cipherlen];
    memset(outplain, 0x00, cipherlen);
    size_t outplainlen = cipherlen;

    unsigned long encrypt_total_time = 0;
    unsigned long decrypt_total_time = 0;

    // 调用times次
    for (int i = 0; i < times; i++) {
        unsigned long encrypt_begin = get_tick_count();

        // GCM 加密
        ret = gcm_encrypt(plain, plainlen, cipher, &cipherlen, tag, &taglen,
                          SM4_GCM_TEST_KEY, sizeof(SM4_GCM_TEST_KEY) * 8,
                          SM4_GCM_TEST_IV, 16, SM4_GCM_TEST_AAD, 16,
                          NO_PADDING, SM4);
        if (ret != RESP_SMCRYPTO_OK) {
            fprintf(stdout, "SM4 GCM asymmetric_encrypt throw error.");
            break;
        }

        unsigned long encrypt_end_or_decrypt_begin = get_tick_count();
        encrypt_total_time += encrypt_end_or_decrypt_begin - encrypt_begin;

        // GCM解密
        ret = gcm_decrypt(cipher, cipherlen, outplain, &outplainlen, tag, taglen,
                          SM4_GCM_TEST_KEY, sizeof(SM4_GCM_TEST_KEY) * 8,
                          SM4_GCM_TEST_IV, 16, SM4_GCM_TEST_AAD, 16,
                          NO_PADDING, SM4);
        if (ret != RESP_SMCRYPTO_OK) {
            fprintf(stdout, "SM4 GCM asymmetric_decrypt throw error.");
            break;
        }

        unsigned long decrypt_end = get_tick_count();
        decrypt_total_time += decrypt_end - encrypt_end_or_decrypt_begin;

        if (outplainlen != plainlen || memcmp(outplain, plain, plainlen)) {
            fprintf(stdout, "SM4 GCM asymmetric_decrypt plain is not equal to plain.");
            break;
        }
    }
    double encrypt_count_per_second = (float) times / (encrypt_total_time / 1000.0);
    double decrypt_count_per_second = (float) times / (decrypt_total_time / 1000.0);

    printf("SM4-GCM asymmetric_encrypt perf:[block size:%lu][tps :%lu][%lf MBps]\n",
           data_length, (long) encrypt_count_per_second, data_length * encrypt_count_per_second / 1024 / 1024);

    printf("SM4-GCM asymmetric_decrypt perf:[block size:%lu][tps :%lu][%lf MBps]\n",
           data_length, (long) decrypt_count_per_second, data_length * decrypt_count_per_second / 1024 / 1024);
}

/**
 * 单元测试：CTR 加密与解密
 */
int test_sm4_ctr_encrypt_decrypt(int times, size_t data_length) {
    int ret = RET_OK;
    size_t plain_len = data_length;
    unsigned char plain[plain_len];
    random_content(plain_len, plain);

    size_t cipher_len = plain_len + 16;
    unsigned char cipher[cipher_len];
    memset(cipher, 0x00, cipher_len);

    unsigned char out_plain[cipher_len];
    memset(out_plain, 0x00, cipher_len);
    size_t out_plain_len = cipher_len;

    unsigned long encrypt_total_time = 0;
    unsigned long decrypt_total_time = 0;

    // 调用times次
    for (int i = 0; i < times; i++) {
        unsigned long encrypt_begin = get_tick_count();
        ret = ctr_encrypt(plain, plain_len, cipher, &cipher_len,
                          SM4_KEY, 16, SM4_IV, 16, SM4);
        if (ret != RESP_SMCRYPTO_OK) {
            fprintf(stdout, "SM4 CTR asymmetric_encrypt throw error.");
            break;
        }
        unsigned long encrypt_end_or_decrypt_begin = get_tick_count();
        encrypt_total_time += encrypt_end_or_decrypt_begin - encrypt_begin;

        ret = ctr_decrypt(cipher, cipher_len, out_plain, &out_plain_len,
                          SM4_KEY, 16, SM4_IV, 16, SM4);
        if (ret != RESP_SMCRYPTO_OK) {
            fprintf(stdout, "SM4 CTR asymmetric_decrypt throw error.");
            break;
        }
        unsigned long decrypt_end = get_tick_count();
        decrypt_total_time += decrypt_end - encrypt_end_or_decrypt_begin;

        if (out_plain_len != plain_len || memcmp(out_plain, plain, plain_len)) {
            fprintf(stdout, "SM4 CTR enc and dec throw error.");
            ret = RET_ERR;
            break;
        }
    }
    double encrypt_count_per_second = (float) times / (encrypt_total_time / 1000.0);
    double decrypt_count_per_second = (float) times / (decrypt_total_time / 1000.0);

    printf("SM4-CBC asymmetric_encrypt perf:[block size:%lu][tps :%lu][%lf MBps]\n",
           data_length, (long) encrypt_count_per_second, data_length * encrypt_count_per_second / 1024 / 1024);

    printf("SM4-CBC asymmetric_decrypt perf:[block size:%lu][tps :%lu][%lf MBps]\n",
           data_length, (long) decrypt_count_per_second, data_length * decrypt_count_per_second / 1024 / 1024);

    return ret;
}

int main(int argc, char const *argv[]) {
    test_sm4_generate_key(1000);
    test_sm4_ecb_encrypt_decrypt(1000, 2127);
    test_sm4_cbc_encrypt_decrypt(1000, 128);
    test_sm4_gcm_encrypt_decrypt(1000, 128);
    test_sm4_ctr_encrypt_decrypt(1000, 128);
    return 0;
}
