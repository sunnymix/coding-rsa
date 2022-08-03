package com.sunnymix.coding.rsa;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.Map;

/**
 * @author Sunny
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class RsaCodecTest {

    private static final String data = "sunnymix";

    private static final String largeData = "";

    private String publicKey = "";

    private String privateKey = "";

    @BeforeAll
    public void init() {
        System.out.printf("\npublicKey:\t%s\nprivateKey:\t%s\n\n", publicKey, privateKey);
    }

    @Test
    public void testSmallData() throws Throwable {
        byte[] encode = RsaCodec.encrypt(data.getBytes(), publicKey);
        byte[] decode = RsaCodec.decrypt(encode, privateKey);
        String output = new String(decode);
        System.out.printf("\nin:\t\t%s\nout:\t%s\n\n", data, output);
        Assertions.assertEquals(data, output);
    }

    @Test
    public void testLargeData() throws Throwable {
        byte[] encode = RsaCodec.encrypt(largeData.getBytes(), publicKey);
        byte[] decode = RsaCodec.decrypt(encode, privateKey);
        String output = new String(decode);
        System.out.printf("\nin:\t\t%s\nout:\t%s\n\n", largeData, output);
        Assertions.assertEquals(largeData, output);
    }

    @Test
    public void testRenewKey() throws Throwable {
        Map<String, String> keyMap = RsaCodec.initKey();
        publicKey = keyMap.get(RsaCodec.PUBLIC_KEY);
        privateKey = keyMap.get(RsaCodec.PRIVATE_KEY);
        System.out.printf("\nrenew key,\npublicKey:\t%s\nprivateKey:\t%s\n\n", publicKey, privateKey);
        testSmallData();
    }

    @Test
    public void testJsEncrypt() throws Throwable {
        String jsContent = "";
        String jsEncrypted = "";
        byte[] decode = RsaCodec.decrypt(Base64.decodeBase64(jsEncrypted), privateKey);
        String output = new String(decode);
        System.out.printf("\nin:\t\t%s\nout:\t%s\n\n", jsContent, output);
        Assertions.assertEquals(jsContent, output);
    }

}
