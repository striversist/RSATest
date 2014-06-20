package com.example.rsatest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        test();
//        testSign();
        testOpenssl();
    }

    public void test() {
        try {
            KeyPairGenerator keyPairGen;
            keyPairGen = KeyPairGenerator.getInstance("RSA");
            // 密钥位数
            keyPairGen.initialize(2048);
            // 密钥对
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // 公钥
            PublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 私钥
            PrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            // 加解密类
            Cipher cipher = Cipher.getInstance("RSA"); // Cipher.getInstance("RSA/ECB/PKCS1Padding");

            // 明文
            byte[] plainText = "我们都很好！邮件：@sina.com".getBytes();

            // 加密
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] enBytes = cipher.doFinal(plainText);

            // 解密
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] deBytes = cipher.doFinal(enBytes);

            String s = new String(deBytes);
            System.out.println(s);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void testSign() {
        final String Algorithm = "MD5withRSA";  // MD2withRSA/MD5withRSA/SHA1withRSA
        String plain = "你好123@gmail";

        try {
            KeyPairGenerator keyPairGen;
            keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            PublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            PrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            byte[] signData = RSAHelper.signData(plain.getBytes(), privateKey, Algorithm);
            
            boolean verify = RSAHelper.verifySignature(plain.getBytes(), publicKey, Algorithm, signData);
            Log.d("", "" + verify);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    public void testOpenssl() {
        final String DEFAULT_PLAIN_TEXT = "hello world";
        
        final String DEFAULT_ALGORITHM = "MD5withRSA";  // MD2withRSA/MD5withRSA/SHA1withRSA
        
        final String DEFAULT_PUB_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJkCphbPB1TPCdYxr8s2" + "\r" +
                                       "pi/06xIwsSU3MYWBRIbqgWsUQGp9DFJ1N4pf7T/b7qakoNNEiDJPVrNyAKjUPUSB" + "\r" + 
                                       "1wwK5BFSPPrLL1ASnSI4KI6UufyFDKI5tYT0tuSfLSDwmDxJcyowKCeWr2lkr/Xf" + "\r" + 
                                       "H3HeTSDdEOZGTZ9NTu5npPhBEFfr+17rWKcDtJdN+qCbV0+puneFyimQkdloZo2D" + "\r" + 
                                       "BTagrXpfZLq+Osdf90QG/Gjnja6FR4gTfivtRMsPVlWnJyclrgg2D8QYoA6s/Ioh" + "\r" + 
                                       "KgsLF2GDbcDRrpNUkgwcUn9+6g42ZnW6oC2++/eI+QbBrYBmE5WMOSz2rPLtw//x" + "\r" + 
                                       "VwIDAQAB" + "\r";
        
        final String DEFAULT_PRI_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCcmQKmFs8HVM8J" + "\r" +
                                       "1jGvyzamL/TrEjCxJTcxhYFEhuqBaxRAan0MUnU3il/tP9vupqSg00SIMk9Ws3IA" + "\r" +
                                       "qNQ9RIHXDArkEVI8+ssvUBKdIjgojpS5/IUMojm1hPS25J8tIPCYPElzKjAoJ5av" + "\r" + 
                                       "aWSv9d8fcd5NIN0Q5kZNn01O7mek+EEQV+v7XutYpwO0l036oJtXT6m6d4XKKZCR" + "\r" + 
                                       "2WhmjYMFNqCtel9kur46x1/3RAb8aOeNroVHiBN+K+1Eyw9WVacnJyWuCDYPxBig" + "\r" + 
                                       "Dqz8iiEqCwsXYYNtwNGuk1SSDBxSf37qDjZmdbqgLb7794j5BsGtgGYTlYw5LPas" + "\r" + 
                                       "8u3D//FXAgMBAAECggEASlG31xlWEdWnGLUGCbc47XAvHW0ZnMjbw+3nZp1dKCSo" + "\r" + 
                                       "jNW9GR79MGnEkvVOrJl74jPB/51Y1/376eI2MAmWUXgOpyStUfF4grDO1LJL0ruw" + "\r" + 
                                       "TABTKKbJGqPJ/A7OmH1ckfNyrGxmRHhdZExxk6ztwp+o8BPbtsyCqw4ig4ZTvA+z" + "\r" + 
                                       "yVSAsUKQVjDvcB/CAnzVXNUr02GX4UwteG7rKyxsUT/UDbylZ1PkA8U0EIp1WSdm" + "\r" +
                                       "KX6r6nRPx/c2OFjHVBQ/d6cEvuhZEMmgXl3pAWI/+2J4zkCHzpCd+vnMczwF8FYD" + "\r" + 
                                       "BtmaC7BBaInl3M+Ze4k+hkLkGdyY1VWbX/LRN1SGSQKBgQDKoqEekd6DAmpHWjB3" + "\r" + 
                                       "ydYGBXoD/JN+zhdQzZrAUglni3AVeyOjRF3CwqMcf5/TllQ1YxMOeS6TUfo9WMC8" + "\r" + 
                                       "Jeq6993nEJfMUSm0MgkJ5flHE/QwNmCcpKNNvxVHffwRqtXY3WxN3w/21cOzKaDp" + "\r" + 
                                       "YjQewAUtahVktevA5iNYH3/4QwKBgQDF1piBQ3LpmjAUeH/0qrsPtpL7PwLCNa13" + "\r" +
                                       "QuM5jJB9knM2pWPnIdNrZLUG2agemD2skgcRsM7FHntViTKZvFwcbP772Rg2gdiy" + "\r" + 
                                       "kn+OPMEW0MZQ3Dw0DgcQ0vVTvz3A69R0H3nCfguBhuDxng+wS+BKayk1HeCQMQjS" + "\r" + 
                                       "5Xw0vbqrXQKBgQCDyKy8cuWhkmqIKRGodi2pENq/yP4r0+C5/l2Mgk33d2nXrpQI" + "\r" + 
                                       "1KedyHPITwAk3Xm6lsqH+SvfR8tVJmmCc65rFlTMt6/hg096D6htNZGfNkzzJgpD" + "\r" + 
                                       "FZfXMlSmgDr1SoN1XNvY8R8yyudRl9s8rU90SDGVzY5IR0Ah3gpSf3n8fQKBgQCj" + "\r" + 
                                       "k2J3Bni902HLmzJY7s1KGa//ksLKJy2s/R35GFLjsLIYTbmDgsFW+2Z+KnrKCSB9" + "\r" + 
                                       "TiQQKXtdGm3pdE3lNQuH6UsOmxpc/xFX3K8gwPT501cVxnL0q2CGNZboTqhVmegI" + "\r" + 
                                       "t3mqKSOETiwxOnpITwQ9I8tngrOJJTHhhiMjTHhKdQKBgGCOGftPvRW4MZ1e1hME" + "\r" + 
                                       "avd5rAw6sUMZRHCpzHrWYRSLZfRxiQZoMlBcqIYzWmPEYzjte7HL86eB3fkdVpwu" + "\r" +
                                       "U0Mo7UXPucmr05gY0Os5TcUZ1mNzyMZWcM0PDRDY55jyrUZqsq+YOcyGklz4zkii" + "\r" +
                                       "E8Bv9pvAfY9yLga1u2oVAz+M" + "\r";
        
        try {
            PublicKey publicKey = RSAHelper.getPublicKey(DEFAULT_PUB_KEY);
            PrivateKey privateKey = RSAHelper.getPrivateKey(DEFAULT_PRI_KEY);
            byte[] signData = RSAHelper.signData(DEFAULT_PLAIN_TEXT.getBytes(), privateKey, DEFAULT_ALGORITHM);
            boolean verify = RSAHelper.verifySignature(DEFAULT_PLAIN_TEXT.getBytes(), publicKey, DEFAULT_ALGORITHM, signData);
            Log.d("", "" + verify);
            
            byte[] encryptData = RSAHelper.encrypt(DEFAULT_PLAIN_TEXT.getBytes(), publicKey);
            byte[] decryptData = RSAHelper.decrypt(encryptData, privateKey);
            String data = new String(decryptData);
            Log.d("", "" + data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
