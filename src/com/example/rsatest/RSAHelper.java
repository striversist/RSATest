package com.example.rsatest;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import android.util.Base64;

public class RSAHelper {
    public static PublicKey getPublicKey(String key) throws Exception {
        if (key == null)
            return null;

        byte[] keyBytes;
//        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        keyBytes = base64Dec(key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        if (key == null)
            return null;

        byte[] keyBytes;
//        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        keyBytes = base64Dec(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static String getKeyString(Key key) throws Exception {
        if (key == null)
            return null;

         byte[] keyBytes = key.getEncoded();
//         String s = (new BASE64Encoder()).encode(keyBytes);
         String s = base64Enc(keyBytes);
         return s;
    }

    private static byte[] base64Dec(String decStr) {
        return Base64.decode(decStr.getBytes(), Base64.DEFAULT);
    }

    private static String base64Enc(byte[] b) {
        return new String(Base64.encode(b, Base64.DEFAULT));
    }
}
