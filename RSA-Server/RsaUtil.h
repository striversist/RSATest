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

    //����rsaKey
    static int genRsaKey(OPT::RsaKey &stRsaKey);

    /**
     * ǩ������֤
     */
    static string signature(const OPT::RsaKey &stRsaKey, const string &sSrcData);

    /**
     * sSrcData ��ֱ�ӵ���Կ, ������������Կ��MD5����
     */
    static bool verfiy(const OPT::RsaKey &stRsaKey, const string &sSrcData, const string &sSignature);

    static bool extractPublicKey(RSA *pRsa, string &sPublicKey);

    static bool extractPrivateKey(RSA *pRsa, string &sPrivateKey);

    /**
     * ���мӽ��ܣ�Ĭ��ʹ��˽Կ��bUserPrivateKey=falseʱʹ�ù�Կ
     */
    static int encryptData(const OPT::RsaKey &stRsaKey, const string &sInput, string & sOutput, bool bUserPrivateKey = true);

    static int decryptData(const OPT::RsaKey &stRsaKey, const string &sInput, string & sOutput, bool bUserPrivateKey = true);


    /**
     * ͨ��RsaKey�����ݽṹ������RSA����
     */
    static RSA * getRsa(const OPT::RsaKey &stRsaKey, bool bUserPrivate = true);

    static int rsaMD5(const string &sSrcData, string &sMd5);
};

#endif /* RSAUTIL_H_ */
