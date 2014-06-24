/*
 * RsaUtil.h
 *
 *  Created on: 2014-6-13
 *      Author: goodenpei
 */

#ifndef RSAUTIL_H_
#define RSAUTIL_H_
#include "Cache.h"
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

class RsaUtil
{
public:
    RsaUtil();
    virtual ~RsaUtil();

    //生成rsaKey
    static int genRsaKey(OPT::RsaKey &stRsaKey);

    /**
     * 签名和验证
     */
    static string signature(const OPT::RsaKey &stRsaKey, const string &sSrcData);

    /**
     * sSrcData 是直接的秘钥, 函数里面会对秘钥做MD5处理
     */
    static bool verfiy(const OPT::RsaKey &stRsaKey, const string &sSrcData, const string &sSignature);

    static bool extractPublicKey(RSA *pRsa, string &sPublicKey);

    static bool extractPrivateKey(RSA *pRsa, string &sPrivateKey);

    /**
     * 进行加解密，默认使用私钥，bUserPrivateKey=false时使用公钥
     */
    static int encryptData(const OPT::RsaKey &stRsaKey, const string &sInput, string & sOutput, bool bUserPrivateKey = true);

    static int decryptData(const OPT::RsaKey &stRsaKey, const string &sInput, string & sOutput, bool bUserPrivateKey = true);


    /**
     * 通过RsaKey的数据结构够构建RSA对象
     */
    static RSA * getRsa(const OPT::RsaKey &stRsaKey, bool bUserPrivate = true);

    static int rsaMD5(const string &sSrcData, string &sMd5);
};

#endif /* RSAUTIL_H_ */
