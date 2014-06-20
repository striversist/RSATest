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

        test();
        testSign();
    }

    private void test() {
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

    private void testSign() {
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
}
