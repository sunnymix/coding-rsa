package com.sunnymix.coding.rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * @author Sunny
 */
public class RsaCodec {

    public static final String RSA = "RSA";

    public static final String PUBLIC_KEY = "PUBLIC_KEY";

    public static final String PRIVATE_KEY = "PRIVATE_KEY";

    public static Map<String, String> initKey() {
        Map<String, String> keyMap = new HashMap<>(2);
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA);
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            keyMap.put(PUBLIC_KEY, Base64.encodeBase64String(keyPair.getPublic().getEncoded()));
            keyMap.put(PRIVATE_KEY, Base64.encodeBase64String(keyPair.getPrivate().getEncoded()));
        } catch (Throwable ignored) {
        }
        return keyMap;
    }

    public static byte[] encrypt(byte[] data, String key) throws Throwable {
        Cipher cipher = _buildCipher(Cipher.ENCRYPT_MODE, key);
        return _codec(data, cipher);
    }

    public static byte[] decrypt(byte[] data, String key) throws Throwable {
        Cipher cipher = _buildCipher(Cipher.DECRYPT_MODE, key);
        return _codec(data, cipher);
    }

    // --- Private:

    private static Cipher _buildCipher(int mode, String key) throws Throwable {
        byte[] keyBytes = Base64.decodeBase64(key.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        Key privateKey = _buildCipherKey(mode, keyBytes, keyFactory);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(mode, privateKey);
        return cipher;
    }

    private static Key _buildCipherKey(int mode, byte[] key, KeyFactory keyFactory) throws Throwable {
        if (mode == Cipher.ENCRYPT_MODE) {
            KeySpec keySpec = new X509EncodedKeySpec(key);
            return keyFactory.generatePublic(keySpec);
        } else if (mode == Cipher.DECRYPT_MODE) {
            KeySpec keySpec = new PKCS8EncodedKeySpec(key);
            return keyFactory.generatePrivate(keySpec);
        }
        throw new RuntimeException("unknown cipher mode:" + mode);
    }

    private static byte[] _codec(byte[] data, Cipher cipher) throws Throwable {
        return cipher.doFinal(data);
    }

    @Deprecated
    private static byte[] _codec(byte[] data, Cipher cipher, int chunkLen) throws Throwable {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int dataLen = data.length;
        int chunkPage = _calcChunkPage(dataLen, chunkLen);

        if (chunkPage <= 1) {
            return cipher.doFinal(data);
        }

        IntStream.range(0, chunkPage).forEachOrdered(page -> {
            int start = page * chunkLen;
            int end = Math.min((start + chunkLen), dataLen);
            try {
                out.write(cipher.doFinal(data, start, end - start));
            } catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
                throw new RuntimeException(e);
            }
        });

        return out.toByteArray();
    }

    private static int _calcChunkPage(int dataSize, int chunkSize) {
        return (dataSize / chunkSize) + (dataSize % chunkSize == 0 ? 0 : 1);
    }

}
