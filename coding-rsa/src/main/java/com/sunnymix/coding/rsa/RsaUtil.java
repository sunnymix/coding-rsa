package com.sunnymix.coding.rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaUtil {

    public static final String RSA = "RSA";

    public static KeyPair initKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    static String getPublicKey(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return Base64.encodeBase64String(bytes);
    }

    static String getPrivateKey(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return Base64.encodeBase64String(bytes);
    }

    static PublicKey toPublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePublic(keySpec);
    }

    static PrivateKey toPrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKeyBase64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        return keyFactory.generatePrivate(keySpec);
    }

    public static String encrypt(String content, String publicKeyBase64) throws Exception {
        PublicKey publicKey = toPublicKey(publicKeyBase64);
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(content.getBytes());
        return Base64.encodeBase64String(bytes);
    }

    public static byte[] decrypt(String content, String privateKeyBase64) throws Exception {
        PrivateKey privateKey = toPrivateKey(privateKeyBase64);
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(Base64.decodeBase64(content));
        return bytes;
    }


    public static void main(String[] args) {
        try {
            KeyPair keyPair = RsaUtil.initKey();
            String publicKeyBase64 = RsaUtil.getPublicKey(keyPair);
            String privateKeyBase64 = RsaUtil.getPrivateKey(keyPair);
            System.out.println("rsa/public-key/base64:\t" + publicKeyBase64);
            System.out.println("rsa/private-key/base64:\t" + privateKeyBase64);

            // --- encrypt:
            String content = "sunny";
            String encrypted = RsaUtil.encrypt(content, publicKeyBase64);
            System.out.println("\nrsa/content:\t\t\t\t\t" + content);
            System.out.println("rsa/content/encrypted/base64:\t" + encrypted);


            // --- decrypt:
            byte[] privateDecrypt = RsaUtil.decrypt(encrypted, privateKeyBase64);
            System.out.println("rsa/decrypt/content:\t\t\t" + new String(privateDecrypt));

            // --- js-encrypt/decrypt:
            String jsEncryptPublicKeyBase64 = "";
            String jsEncryptPrivateKeyBase64 = "";
            String jsEncryptedContent = "";

            byte[] privateJsDecrypt = RsaUtil.decrypt(jsEncryptedContent, jsEncryptPrivateKeyBase64);
            System.out.println("\nrsa/js-encrypt/public-key-base64:\t" + jsEncryptPublicKeyBase64);
            System.out.println("rsa/js-encrypt/private-key-base64:\t" + jsEncryptPrivateKeyBase64);
            System.out.println("rsa/js-encrypted:\t\t\t\t\t" + jsEncryptedContent);
            System.out.println("rsa/js-encrypted/decrypt:\t\t\t" + new String(privateJsDecrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
