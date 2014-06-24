/*
 * RsaUtil.cpp
 *
 *  Created on: 2014-6-13
 *      Author: goodenpei
 */
#include "RsaUtil.h"
#include "Common.h"
#include <openssl/md5.h>

using namespace OPT;
using namespace taf;

RsaUtil::RsaUtil()
{
    // TODO Auto-generated constructor stub

}

RsaUtil::~RsaUtil()
{
    // TODO Auto-generated destructor stub
}

int RsaUtil::genRsaKey(OPT::RsaKey& stRsaKey)
{
    try
    {
        RSA * pRsa = RSA_new();
        BIGNUM* pBn = BN_new();
        BIO * pBioPriv = NULL;
        //公钥
        BIO * pBioPub = NULL;
        int iRet = -1;

        do
        {
            // set word
            if( 1 != BN_set_word(pBn, 65537) )
            {
                LOG_ERROR << "SET WORD fro bignum failed" << endl;
                iRet = -1;
                break;
            }

            // gen rsa key
            if( 1 != RSA_generate_key_ex(pRsa, 2048, pBn, 0) )
            {
                LOG_ERROR << "generate rsa key failed" << endl;
                iRet = -2;
                break;
            }
            // read private key
            if( !extractPrivateKey(pRsa, stRsaKey.sPrivateKey) )
            {
                iRet = -3;
                break;
            }
            // read pub key
            if( !extractPublicKey(pRsa, stRsaKey.sPublicKey) )
            {
                iRet = -5;
                break;
            }
            iRet = 0;

            LOG_DEBUG << "GEN RSA KEY SUCC! private key len=" << stRsaKey.sPrivateKey.length()
                    << ",public key len=" << stRsaKey.sPublicKey.length() << endl;

        }while(0);

        //清理内存
        RSA_free(pRsa);
        BN_free(pBn);
        if(NULL != pBioPriv)
        {
            BIO_free(pBioPriv);
        }
        if(NULL != pBioPub)
        {
            BIO_free(pBioPub);
        }
        return iRet;

    }
    catch(exception &ex)
    {
        LOG_ERROR<< "exception:" << ex.what() << endl;
    }
    catch(...)
    {
        LOG_ERROR<< "unkown exception" << endl;
    }
    return -1;
}


string RsaUtil::signature(const OPT::RsaKey& stRsaKey, const string& sSrcData)
{
    string sSignature = "";
    try
    {
        string sSrcMd5;
        if( 0 != rsaMD5(sSrcData, sSrcMd5) )
        {
            LOG_ERROR << "rsaMD5 FAILED" << endl;
            return false;
        }

        BIO * pPrivKey = BIO_new(BIO_s_mem());
        if( NULL == pPrivKey )
        {
            LOG_ERROR << "pPrivKey failed" << endl;
            return "";
        }

        if( BIO_write(pPrivKey, stRsaKey.sPrivateKey.c_str(), stRsaKey.sPrivateKey.length()) <= 0)
        {
            LOG_ERROR << "bio write failed" << endl;
            BIO_free(pPrivKey);
            return "";
        }

        RSA * rsa = RSA_new();
        if( NULL == rsa)
        {
            LOG_ERROR << "RSA_new failed" << endl;
            BIO_free(pPrivKey);
            return "";
        }
        rsa = PEM_read_bio_RSAPrivateKey(pPrivKey, &rsa,NULL, NULL);
        if( rsa->d != NULL)
        {
            ////////////////////rsa是2048字节的，所以需要签名是256字节
            unsigned char ptext[256+1];
            unsigned int iRetLen = 0;
            memset( ptext, 0, sizeof(ptext) ) ;
            if(1 == RSA_sign(NID_md5, (const unsigned char*)sSrcMd5.c_str(), sSrcMd5.length(), ptext, &iRetLen, rsa) && iRetLen > 0)
            {
                sSignature.assign((const char *)ptext, iRetLen);

                LOG_DEBUG << "retlen=" << iRetLen << ",signature length=" << sSignature.length() << endl;
            }
            else
            {
                unsigned long errcode = ERR_get_error();
                LOG_ERROR << "RSA_sign failed:" << ERR_error_string(errcode, NULL) << endl;
            }
        }
        RSA_free(rsa);
        BIO_free(pPrivKey);
    }
    catch(exception &ex)
    {
        LOG_ERROR<< "exception:" << ex.what() << endl;
    }
    catch(...)
    {
        LOG_ERROR<< "unkown exception" << endl;
    }
    return sSignature;
}

bool RsaUtil::verfiy(const OPT::RsaKey& stRsaKey, const string& sSrcData,
        const string& sSignature)
{
    try
    {
        if(sSignature.length() > 256)
        {
            LOG_ERROR << "signature too long, length=" << sSignature.length() << endl;
            return false;
        }

        string sSrcMd5;
        if( 0 != rsaMD5(sSrcData, sSrcMd5) )
        {
            LOG_ERROR << "rsaMD5 FAILED" << endl;
            return false;
        }

        BIO * pPubKey = BIO_new(BIO_s_mem());

        if( NULL == pPubKey )
        {
            LOG_ERROR << "new public key failed" << endl;
            return false;
        }

        if(BIO_write(pPubKey, stRsaKey.sPublicKey.c_str(), stRsaKey.sPublicKey.length()) <= 0)
        {
            LOG_ERROR << "bio write failed" << endl;
            BIO_free(pPubKey);
            return false;
        }

        RSA * rsa = RSA_new();
        if(NULL == rsa)
        {
            LOG_ERROR << "RSA_new failed" << endl;
            BIO_free(pPubKey);
            return false;
        }
        rsa = PEM_read_bio_RSA_PUBKEY(pPubKey, &rsa, NULL, NULL);
//        rsa = PEM_read_bio_RSAPublicKey(pPubKey, &rsa,NULL, NULL);
        int iRet = 0;
        if( rsa != NULL )
        {
            unsigned char sigbuf[257]={0};
            memcpy(sigbuf, sSignature.c_str(), sSignature.length());
            iRet = RSA_verify(NID_md5, (const unsigned char*)sSrcMd5.c_str(),
                    sSrcMd5.length(), sigbuf, sSignature.length(), rsa);
            if( 1 != iRet )
            {
                unsigned long errcode;
                while( (errcode = ERR_get_error()) != 0 )
                {
                    LOG_ERROR << "RSA_verify failed:" << ERR_error_string(errcode, NULL) << endl;
                }
            }

        }
        else
        {
            unsigned long errcode = ERR_get_error();
            LOG_ERROR << "READ PUBLIC KEY FAILED:" << ERR_error_string(errcode, NULL) << endl;
        }
        RSA_free(rsa);
        BIO_free(pPubKey);

        return 1 == iRet;
    }
    catch(exception &ex)
    {
        LOG_ERROR<< "exception:" << ex.what() << endl;
    }
    catch(...)
    {
        LOG_ERROR<< "unkown exception" << endl;
    }
    return false;
}



int RsaUtil::encryptData(const OPT::RsaKey& stRsaKey, const string& sInput, string& sOutput, bool bUserPrivateKey)
{
    try
    {
        if(sInput.empty())
        {
            LOG_ERROR << "empty data" << endl;
            return -1;
        }
        LOG_DEBUG << "bUserPrivateKey=" << bUserPrivateKey << ",pub key len=" << stRsaKey.sPublicKey.length()
                    << ",private key=" << stRsaKey.sPrivateKey.length() << endl;

        RSA * rsa = getRsa(stRsaKey, bUserPrivateKey);
        if( NULL == rsa )
        {
            LOG_ERROR << "getRsa error" << endl;
            return -1;
        }
        int iRet = 0;

        unsigned int uiMaxInputSize = RSA_size(rsa) - 11;
        if(sInput.length() > uiMaxInputSize)
        {
            LOG_ERROR << "input too large, len=" << sInput.length() << ",max size=" << uiMaxInputSize << endl;
        }
        else
        {
            unsigned int uiOutSize = RSA_size(rsa);
            unsigned char *pOutBuf = new unsigned char[ uiOutSize+1 ];
            memset( pOutBuf, 0, uiOutSize+1 ) ;

            if( bUserPrivateKey )
            {
                iRet = RSA_private_encrypt(sInput.length(), (unsigned char*)sInput.c_str(), pOutBuf, rsa, RSA_PKCS1_PADDING);
            }
            else
            {
                iRet = RSA_public_encrypt(sInput.length(), (unsigned char*)sInput.c_str(), pOutBuf, rsa, RSA_PKCS1_PADDING);
            }
            if( iRet <= 0 )
            {
                unsigned long errcode = ERR_get_error();
                LOG_ERROR << "RSA_private_encrypt failed:" << ERR_error_string(errcode, NULL) << endl;
            }
            else
            {
                sOutput.assign((const char*)pOutBuf, iRet);
            }
            delete [] pOutBuf;
        }

        RSA_free(rsa);
        return iRet > 0 ? 0 : -1;
    }
    catch(exception &ex)
    {
        LOG_ERROR<< "exception:" << ex.what() << endl;
    }
    catch(...)
    {
        LOG_ERROR<< "unkown exception" << endl;
    }
    return -6;
}

int RsaUtil::decryptData(const OPT::RsaKey& stRsaKey, const string& sInput, string& sOutput, bool bUserPrivateKey)
{
    try
    {
        if(sInput.empty())
        {
            LOG_ERROR << "empty data" << endl;
            return -1;
        }
        LOG_DEBUG << "bUserPrivateKey=" << bUserPrivateKey << ",pub key len=" << stRsaKey.sPublicKey.length()
                << ",private key=" << stRsaKey.sPrivateKey.length() << endl;

        RSA * rsa = getRsa(stRsaKey, bUserPrivateKey);
        if( NULL == rsa )
        {
            LOG_ERROR << "getRsa error" << endl;
            return -1;
        }
        int iRet = 0;
        if(sInput.length() > (unsigned int)RSA_size(rsa))
        {
            LOG_ERROR << "input too large, len=" << sInput.length() << ",max size=" << RSA_size(rsa) << endl;
        }
        else
        {
            unsigned int uiOutSize = RSA_size(rsa) - 11;
            unsigned char *pOutBuf = new unsigned char[uiOutSize+1];
            memset( pOutBuf, 0, uiOutSize+1 ) ;

            if( bUserPrivateKey )
            {
                iRet = RSA_private_decrypt(sInput.length(), (unsigned char*)sInput.c_str(), pOutBuf, rsa, RSA_PKCS1_PADDING);
            }
            else
            {
                iRet = RSA_public_decrypt(sInput.length(), (unsigned char*)sInput.c_str(), pOutBuf, rsa, RSA_PKCS1_PADDING);
            }
            if( iRet <= 0 )
            {
                unsigned long errcode = ERR_get_error();
                LOG_ERROR << "RSA_public_decrypt failed:" << ERR_error_string(errcode, NULL) << endl;
            }
            else
            {
                sOutput.assign((const char*)pOutBuf, iRet);
            }
            delete [] pOutBuf;
        }

        RSA_free(rsa);
        return iRet > 0 ? 0 : -1;
    }
    catch(exception &ex)
    {
        LOG_ERROR<< "exception:" << ex.what() << endl;
    }
    catch(...)
    {
        LOG_ERROR<< "unkown exception" << endl;
    }
    return -6;
}


bool RsaUtil::extractPublicKey(RSA* pRsa, string& sPublicKey)
{
    BIO * pBioPub = BIO_new(BIO_s_mem());
    if( 1 != PEM_write_bio_RSA_PUBKEY(pBioPub, pRsa) )
    {
        LOG_ERROR << "get public key buffer failed" << endl;
        return false;
    }

    unsigned long ulWrote = BIO_number_written(pBioPub);
    sPublicKey.resize(ulWrote);

    unsigned long ulReadRet = BIO_read(pBioPub, &(sPublicKey[0]), ulWrote);
    if ( ulReadRet != ulWrote)
    {
        LOG_ERROR << "read private key buffer failed" << endl;
        return false;
    }
    return true;
}

bool RsaUtil::extractPrivateKey(RSA* pRsa, string& sPrivateKey)
{
    BIO * pBioPriv = BIO_new(BIO_s_mem());
    if( 1 != PEM_write_bio_RSAPrivateKey(pBioPriv, pRsa, 0, 0, 0, 0, 0) )
    {
        LOG_ERROR << "get private key buffer failed" << endl;
        return false;
    }

    unsigned long ulWrote = BIO_number_written(pBioPriv);

    sPrivateKey.resize(ulWrote);

    unsigned long ulReadRet = BIO_read(pBioPriv, &(sPrivateKey[0]), ulWrote);
    if ( ulReadRet != ulWrote)
    {
        LOG_ERROR << "read private key buffer failed" << endl;
        return false;
    }
    return true;
}


RSA* RsaUtil::getRsa(const OPT::RsaKey& stRsaKey, bool bUserPrivate)
{
    BIO * pKey = BIO_new(BIO_s_mem());
    if( NULL == pKey )
    {
        LOG_ERROR << "pPrivKey failed" << endl;
        return NULL;
    }
    string sKeyInStr = bUserPrivate ? stRsaKey.sPrivateKey : stRsaKey.sPublicKey;
    if( BIO_write(pKey, sKeyInStr.c_str(), sKeyInStr.length()) <= 0)
    {
        LOG_ERROR << "bio write failed" << endl;
        BIO_free(pKey);
        return NULL;
    }

    RSA * rsa = RSA_new();
    if( NULL == rsa)
    {
        LOG_ERROR << "RSA_new failed" << endl;
        BIO_free(pKey);
        return NULL;
    }
    if( bUserPrivate )
    {
        rsa = PEM_read_bio_RSAPrivateKey(pKey, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSA_PUBKEY(pKey, &rsa,NULL, NULL);
    }


    BIO_free(pKey);
    return rsa;
}

int RsaUtil::rsaMD5(const string& sSrcData, string &sMd5)
{
    MD5_CTX md5_ctx={0};
    unsigned char md[MD5_DIGEST_LENGTH+1];
    int rc = MD5_Init(&md5_ctx);
    if(rc != 1)
    {
        LOG_ERROR << "MD5_Init failed" << endl;
        return -1;
    }

    rc = MD5_Update(&md5_ctx, (const void *)sSrcData.c_str(), sSrcData.length());
    if(rc != 1)
    {
        LOG_ERROR << "MD5_Update failed" << endl;
        return -1;
    }
    rc = MD5_Final(md, &md5_ctx);
    if(rc != 1)
    {
        LOG_ERROR << "MD5_Final failed" << endl;
        return -1;
    }
    sMd5.assign((const char *)md, MD5_DIGEST_LENGTH);
    return 0;
}
