#ifndef SMLITEALL_API_H
#define SMLITEALL_API_H


#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif
#undef SMCRYPTO_EXPORT
#if defined (_WIN32) && !defined (_WIN_STATIC)
#if !defined(SMCRYPTO_EXPORTS)
#define  SMCRYPTO_EXPORT __declspec(dllexport)
#else
#define  SMCRYPTO_EXPORT __declspec(dllimport)
#endif
#else /* defined (_WIN32) */
#define SMCRYPTO_EXPORT
#endif

/**
 * SM2 上下文信息
 */
typedef struct {
    // 椭圆曲线系统相关参数，实际类型 sm_ec_group_t
    void *group;

    // 基点，实际类型 sm_ecc_point_st
    void *generator;

    // Jacobian加重射影坐标系基点，实际类型 sm_ecc_jcb_point_st
    void *jcb_generator;

    // Jacobian加重射影坐标系下中间计算结果，实际类型 sm_ecc_jcb_point_st
    void *jcb_compute_var;

    // 大整数缓存数组，加锁时使用到，见函数sm_lock_temp_bn，实际类型 sm_bn_t
    void *bn_vars;

    // ECC点缓存数组，加锁时使用到，见函数sm_lock_temp_ec，实际类型 sm_ec_t
    void *ec_vars;

    // 暂无用，实际类型 ec_pre_comp_st
    void *pre_comp_g;

    // 多倍点运算预先计算结果，用于加速，实际类型 ec_pre_comp_st
    void *pre_comp_p;

    // 伪随机数生成器上下文，实际类型 rand_ctx_t
    void *rand_ctx;

    // 带公钥上下文初始化接口入参公钥x轴值，实际类型 char *
    void *pubkey_x;

    // 带公钥上下文初始化接口入参公钥y轴值，实际类型 char *
    void *pubkey_y;

    // 用于签名的随机数，实际类型 char *
    void *sign_random;
} sm2_ctx_t;


/*
 * SM3 Hash摘要上下文
 */
typedef struct {
    // ABCDEFGH 寄存器信息，用于组成最终摘要值
    uint32_t digest[8];
    // 消息block数
    uint32_t nblocks;
    // 消息分组
    unsigned char block[64];
    // 记录已hash消息长度
    uint32_t num;
} sm3_ctx_t;


/**
 * 非对称加密
 */
typedef enum {
    SM2,
    CRYSTALS_KYBER,
    ASYMMETRIC_CRYPT_MAX
} asymmetric_cryptograph_t;

/**
 * 数字签名算法
 */
typedef enum {
    SM2_SIGN,
    CRYSTALS_DILITHIUM,
    FALCON,
    SPHINCS_PLUS,
    SIGNATURE_ALGO_MAX
} signature_algorithm_t;



/**
 *  SM2上下文ctx初始化接口。

 在使用SM2接口进行密钥生成、加密解密、签名验签之前，必须调用该接口。
 该接口只需调用一次，在后续的密钥生成、加密解密、签名验签运算中，无需再次调用该接口。
 该接口所涉及ctx不是线程安全的，如需支持多线程，可对涉及ctx参数的接口调用加锁以保证线程安全，或不同线程使用不同的ctx。
 如需支持多线程，推荐在不同线程使用不同的ctx，以防止加锁带来的性能损耗。
 * @param sm2_ctx 函数出参 - 上下文
 * @return 0表示成功，其他值为错误
 */
SMCRYPTO_EXPORT int init_sm2_ctx(sm2_ctx_t *sm2_ctx);


/**
 使用完SM2算法后，必须调用SM2FreeCtx函数释放相关数据。
 如果ctx需要在整个线程生命周期复用的话，可在线程退出前释放。
 */
SMCRYPTO_EXPORT int free_sm2_ctx(sm2_ctx_t *sm2_ctx);


/**
 生成私钥
 @param output_private_key  函数出参 - 私钥
 @param private_key_len  函数出参 - 私钥长度
 @param type 函数入参 - 加密算法类型，可选SM2、RSA、后量子密码算法等
 @return  0表示成功，其他值为错误码
*/
SMCRYPTO_EXPORT int generate_private_key(char *output_private_key,
                                         size_t *private_key_len,
                                         asymmetric_cryptograph_t type);


/**
 * 生成私钥
 * @param sm2_ctx SM2上下文
 * @param output_private_key 函数出参 - 私钥
 * @param private_key_len 函数出参 - 私钥长度
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int generate_private_key_ctx(sm2_ctx_t *sm2_ctx,
                                             char *output_private_key,
                                             size_t *private_key_len);


/**
 根据私钥生成对应公钥，
 @param private_key 函数入参 - 私钥
 @param private_key_len  函数入参 - 私钥长度
 @param output_public_key 函数出参 - 公钥
 @param public_key_len  函数出参 - 公钥长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 @return  0表示成功，其他值为错误码
*/
SMCRYPTO_EXPORT int generate_public_key(const char *private_key,
                                        size_t private_key_len,
                                        char *output_public_key,
                                        size_t *public_key_len,
                                        asymmetric_cryptograph_t type);

/**
 根据私钥生成对应公钥，
 @param sm2_ctx SM2上下文
 @param private_key 函数入参 - 私钥
 @param private_key_len  函数入参 - 私钥长度
 @param output_public_key 函数出参 - 公钥
 @param public_key_len  函数出参 - 公钥长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 @return  0表示成功，其他值为错误码
*/
SMCRYPTO_EXPORT int generate_public_key_ctx(sm2_ctx_t *sm2_ctx,
                                            const char *private_key,
                                            size_t private_key_len,
                                            char *output_public_key,
                                            size_t *public_key_len);

/**
 生成公私钥对
 @param private_key 函数出参 - 私钥
 @param private_key_len  函数出参 - 私钥长度
 @param public_key 函数出参 - 公钥
 @param public_key_len  函数出参 - 公钥长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 @return  0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int generate_key_pair(char *private_key,
                                      size_t *private_key_len,
                                      char *public_key,
                                      size_t *public_key_len,
                                      asymmetric_cryptograph_t type);


/**
 生成公私钥对
 @param sm2_ctx SM2上下文
 @param private_key 函数出参 - 私钥
 @param private_key_len  函数出参 - 私钥长度
 @param public_key 函数出参 - 公钥
 @param public_key_len  函数出参 - 公钥长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 @return  0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int generate_key_pair_ctx(sm2_ctx_t *sm2_ctx,
                                          char *private_key,
                                          size_t *private_key_len,
                                          char *public_key,
                                          size_t *public_key_len);

/**
 加密
 @param input  函数入参 - 待加密消息
 @param input_len  函数入参 - 消息长度(字节单位)
 @param str_public_key  函数入参 - 公钥
 @param public_key_len  函数入参 - 公钥长度
 @param output  函数出参 - 密文
 @param output_len  函数入参和出参 - 密文长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 @return  0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int asymmetric_encrypt(const unsigned char *input,
                                       size_t input_len,
                                       const char *str_public_key,
                                       size_t public_key_len,
                                       unsigned char *output,
                                       size_t *output_len,
                                       asymmetric_cryptograph_t type);

SMCRYPTO_EXPORT int asymmetric_encrypt_ctx(sm2_ctx_t *sm2_ctx,
                                           const unsigned char *input,
                                           size_t input_len,
                                           const char *str_public_key,
                                           size_t public_key_len,
                                           unsigned char *output,
                                           size_t *output_len);


/**
 解密
 @param input  函数入参 - 待解密密文
 @param input_len  函数入参 - 密文长度(字节单位)
 @param str_private_key  函数入参 - 私钥
 @param private_key_len  函数入参 - 私钥长度
 @param output  函数出参 - 明文
 @param output_len  函数入参和出参 - 明文长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 @return  0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int asymmetric_decrypt(const unsigned char *input,
                                       size_t input_len,
                                       const char *str_private_key,
                                       size_t private_key_len,
                                       unsigned char *output,
                                       size_t *output_len,
                                       asymmetric_cryptograph_t type);

SMCRYPTO_EXPORT int asymmetric_decrypt_ctx(sm2_ctx_t *sm2_ctx,
                                           const unsigned char *input,
                                           size_t input_len,
                                           const char *str_private_key,
                                           size_t private_key_len,
                                           unsigned char *output,
                                           size_t *output_len);



/**
 签名
 @param msg 函数入参 - 待签名消息
 @param msg_len 函数入参 - 待签名消息长度
 @param id 函数入参 - 用户ID(作用是加入到签名hash中，对于传入值无特殊要求)
 @param id_len 函数入参 - 用户ID长度
 @param public_key 函数入参 - 公钥(作用是加入到签名hash中)
 @param public_key_len 函数入参 - 公钥长度
 @param private_key 函数入参 - 私钥
 @param private_key_len 函数入参 - 私钥长度
 @param signature 函数出参 - 签名结果
 @param signature_len 函数入参和出参 - 签名结果长度
 @param type 函数入参 - 加密算法类型，可选sm2、rsa、后量子密码算法等
 */
SMCRYPTO_EXPORT int sign(const unsigned char *msg,
                         size_t msg_len,
                         const char *id,
                         size_t id_len,
                         const char *public_key,
                         size_t public_key_len,
                         const char *private_key,
                         size_t private_key_len,
                         unsigned char *signature,
                         size_t *signature_len,
                         signature_algorithm_t type);

SMCRYPTO_EXPORT int sign_ctx(sm2_ctx_t *sm2_ctx,
                             const unsigned char *msg,
                             size_t msg_len,
                             const char *id,
                             size_t id_len,
                             const char *public_key,
                             size_t public_key_len,
                             const char *private_key,
                             size_t private_key_len,
                             unsigned char *signature,
                             size_t *signature_len);

/**
 验签
 @param msg 函数入参 - 待验签内容
 @param msg_len 函数入参 - 待验签内容长度
 @param id 函数入参 - 用户ID
 @param id_len 函数入参 - 用户ID长度
 @param signature 函数入参 - 签名结果
 @param signature_len 函数入参 - 签名结果长度
 @param public_key 函数入参 - 公钥
 @param public_key_len 函数入参 - 公钥长度
 @param type 函数入参 - 加密算法类型，可选SM2、RSA、后量子密码算法等
 @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int verify(const unsigned char *msg,
                           size_t msg_len,
                           const char *id,
                           size_t id_len,
                           const unsigned char *signature,
                           size_t signature_len,
                           const char *public_key,
                           size_t public_key_len,
                           signature_algorithm_t type);


SMCRYPTO_EXPORT int verify_ctx(sm2_ctx_t *sm2_ctx,
                               const unsigned char *msg,
                               size_t msg_len,
                               const char *id,
                               size_t id_len,
                               const unsigned char *signature,
                               size_t signature_len,
                               const char *public_key,
                               size_t public_key_len);

typedef enum {
    SM3_CRYPTO,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_512_224,
    SHA_512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
    KECCAK,
} hash_algorithm_t;


/**
 * 计算摘要值
 * @param data 函数入参 - 计算的数据
 * @param data_len 函数入参 - 数据长度
 * @param digest  函数出参 - 输出的摘要值
 * @param digest_len  函数出参 - 输出的摘要值长度
 * @param type 函数入参 - Hash算法类型，可选sm3、SHA3等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int hash_digest(const unsigned char *data,
                                size_t data_len,
                                unsigned char *digest,
                                size_t *digest_len,
                                hash_algorithm_t type);

/**
 * 计算HMAC值
 * @param data 做HMAC计算的数据
 * @param data_len 数据长度
 * @param key HMAC用的秘钥
 * @param key_len 秘钥长度
 * @param mac 输出的HMAC字节码
 * @param mac_size 输出的HMAC长度
 * @param type 函数入参 - Hash算法类型，可选sm3、SHA3、后量子密码算法等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int hmac(const unsigned char *data,
                         size_t data_len,
                         const unsigned char *key,
                         size_t key_len,
                         unsigned char *mac,
                         size_t *mac_size, hash_algorithm_t type);


/**
 * 非对称密码
 */
typedef enum {
    SM4,
} symmetric_cryptograph_t;

/**
 * 是否有填充
 */
typedef enum {
    PADDING,
    NO_PADDING,
} padding_t;


/**
 生成对称算法密钥
 * @param output_key  函数出参 - 密钥
 * @param key_len  函数出参 - 密钥长度
 * @param type 函数入参 - 对称算法类型，可选sm4、AES等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int generate_symmetric_key(unsigned char *output_key,
                                           size_t *key_len,
                                           symmetric_cryptograph_t type);

/**
 * ECB模式对称加解密。加密
 * @param input 函数入参 - 明文
 * @param input_len 函数入参 - 明文长度
 * @param output 函数出参 - 密文
 * @param output_len 函数出参 - 密文长度
 * @param key 函数入参 - 秘钥
 * @param key_len  函数入参 - 秘钥长度
 * @param padding 函数入参 - 待加密数据是否有填充，如有填充，则为1；没有填充，则为0
 * @param type 函数入参 - 对称算法类型，可选sm4、AES、后量子密码算法等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int ecb_encrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *key,
                                size_t key_len,
                                padding_t padding,
                                symmetric_cryptograph_t type);


/**
 * ECB模式对称加解密。解密
 * @param input 函数入参 - 密文
 * @param input_len 函数入参 - 密文长度
 * @param output 函数出参 - 明文
 * @param output_len 函数出参 - 明文长度
 * @param key 函数入参 - 秘钥
 * @param key_len  函数入参 - 秘钥长度
 * @param padding 函数入参 - 待加密数据是否有填充，如有填充，则为1；没有填充，则为0
 * @param type 函数入参 - 对称算法类型，可选sm4、AES、后量子密码算法等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int ecb_decrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *key,
                                size_t key_len,
                                padding_t padding,
                                symmetric_cryptograph_t type);

/**
 CBC模式对称加解密。加密，如果有填充，则使用PKCS#7填充标准。
 * @param input  函数入参 - 明文
 * @param input_len  函数入参 - 明文长度
 * @param output  函数出参 - 密文
 * @param output_len  函数出参 - 密文长度
 * @param key  函数入参 - 秘钥
 * @param key_len  函数入参 - 秘钥长度
 * @param iv  函数入参 - 初始化向量
 * @param iv_len  函数入参 - 初始化向量长度
 * @param padding 函数入参 - 待加密数据是否有填充，如有填充，则为1；没有填充，则为0
 * @param type 函数入参 - 对称算法类型，可选sm4、AES等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int cbc_encrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *key,
                                size_t key_len,
                                const unsigned char *iv,
                                size_t iv_len,
                                padding_t padding,
                                symmetric_cryptograph_t type);

/**
 CBC模式对称加解密。解密，如果有填充，则使用PKCS#7填充标准
 * @param input  函数入参 - 密文
 * @param input_len  函数入参 - 密文长度
 * @param output  函数出参 - 明文
 * @param output_len  函数出参 - 明文长度
 * @param key  函数入参 - 秘钥
 * @param key_len  函数入参 - 秘钥长度
 * @param iv  函数入参 - 初始化向量
 * @param iv_len  函数入参 - 初始化向量长度
 * @param padding 函数入参 - 待加密数据是否有填充，如有填充，则为1；没有填充，则为0
 * @param type 函数入参 - 对称算法类型，可选sm4、AES等
 * @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int cbc_decrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *key,
                                size_t key_len,
                                const unsigned char *iv,
                                size_t iv_len,
                                padding_t padding,
                                symmetric_cryptograph_t type);
/**
 GCM模式对称加解密。加密，若有填充，则使用PKCS7填充
 @param input  函数入参 - 明文
 @param input_len  函数入参 - 明文长度
 @param output  函数出参 - 密文
 @param output_len  函数出参 - 密文长度
 @param tag  函数出参 - GMAC值，即消息验证码
 @param tag_len  既作函数入参也作为函数出参 - GMAC长度
 @param key  函数入参 - 秘钥
 @param key_len  函数入参 - 秘钥长度
 @param iv  函数入参 - 初始化向量
 @param iv_len  函数入参 - 初始化向量长度
 @param aad  函数入参 - 附加验证消息
 @param aad_len  函数入参 - 附加验证消息长度
 @param padding 函数入参 - 待加密数据是否有填充，如有填充，则为1；没有填充，则为0
 @param type 函数入参 - 对称算法类型，可选sm4、AES、后量子密码算法等
 @return 成功为0，一般加密失败是由参数错误导致
*/
SMCRYPTO_EXPORT int gcm_encrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                unsigned char *tag,
                                size_t *tag_len,
                                const unsigned char *key,
                                size_t key_len,
                                const unsigned char *iv,
                                size_t iv_len,
                                const unsigned char *aad,
                                size_t aad_len,
                                padding_t padding,
                                symmetric_cryptograph_t type);

/**
 GCM模式对称加解密。解密，若有填充，则使用PKCS7填充
 @param input  函数入参 - 密文
 @param input_len  函数入参 - 密文长度
 @param output  函数出参 - 明文
 @param output_len  函数出参 - 明文长度
 @param tag  函数入参 - GMAC值，即消息验证码
 @param tag_len  函数入参 - GMAC长度，通常取16字节
 @param key  函数入参 - 秘钥
 @param key_len  函数入参 - 秘钥长度
 @param iv  函数入参 - 初始化向量
 @param iv_len  函数入参 - 初始化向量长度
 @param aad  函数入参 - 附加验证消息
 @param aad_len  函数入参 - 附加验证消息长度
 @return 成功为0，GCM的解密失败主要是tag校验失败
*/
SMCRYPTO_EXPORT int gcm_decrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *tag,
                                size_t tag_len,
                                const unsigned char *key,
                                size_t key_len,
                                const unsigned char *iv,
                                size_t iv_len,
                                const unsigned char *aad,
                                size_t aad_len,
                                padding_t padding,
                                symmetric_cryptograph_t type);

/**
 CTR模式对称加解密。加密，CTR模式不需要填充。
 @param input 函数入参 - 明文
 @param input_len 函数入参 - 明文长度
 @param output 函数出参 - 密文
 @param output_len 函数出参 - 密文长度
 @param key  函数入参 - 秘钥
 @param key_len  函数入参 - 秘钥长度
 @param iv  函数入参 - 初始化向量
 @param iv_len  函数入参 - 初始化向量长度
 @param type 函数入参 - 对称算法类型，可选sm4、AES、后量子密码算法等
 @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int ctr_encrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *key,
                                size_t key_len,
                                const unsigned char *iv,
                                size_t iv_len,
                                symmetric_cryptograph_t type);

/**
 CTR模式对称加解密。解密，CTR模式不需要填充。
 @param input  函数入参 - 密文
 @param input_len  函数入参 - 密文长度
 @param output  函数出参 - 明文
 @param output_len  函数出参 - 明文长度
 @param key  函数入参 - 秘钥
 @param key_len  函数入参 - 秘钥长度
 @param iv  函数入参 - 初始化向量
 @param iv_len  函数入参 - 初始化向量长度
 @param type 函数入参 - 对称算法类型，可选sm4、AES、后量子密码算法等
 @return 0表示成功，其他值为错误码
 */
SMCRYPTO_EXPORT int ctr_decrypt(const unsigned char *input,
                                size_t input_len,
                                unsigned char *output,
                                size_t *output_len,
                                const unsigned char *key,
                                size_t key_len,
                                const unsigned char *iv,
                                size_t iv_len,
                                symmetric_cryptograph_t type);



/**
 SM3 hash算法，3个接口用法与OpenSSL的MD5算法的接口保持一致。
 digest至少需要分配32字节
 */
SMCRYPTO_EXPORT int SM3Init(sm3_ctx_t *ctx);

SMCRYPTO_EXPORT int SM3Update(sm3_ctx_t *ctx, const unsigned char *data, size_t data_len);

SMCRYPTO_EXPORT int SM3Final(sm3_ctx_t *ctx, unsigned char *digest);


#ifdef  __cplusplus
}
#endif

#endif //SMLITEALL_API_H