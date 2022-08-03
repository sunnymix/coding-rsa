package com.sunnymix.coding.rsa;

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

    private static final String largeData = "sunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymixsunnymix";

    private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDs+SfHVT2dWL6sbUOg7zFh/nbtltf2UPvh2W2EJdGGawbv0Z8ekcd/aSA40VlK8apf0/gaywpphCJXbbpwzOTYUDoeYewaSpzhTEuIbGcZzoiSi9vjhV7PoZueu45X0kOZ7skxUDbriIRPzuUG1ahwuneGPdVOSUIrEixyxIAfwQIDAQAB";

    private String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOz5J8dVPZ1YvqxtQ6DvMWH+du2W1/ZQ++HZbYQl0YZrBu/Rnx6Rx39pIDjRWUrxql/T+BrLCmmEIldtunDM5NhQOh5h7BpKnOFMS4hsZxnOiJKL2+OFXs+hm567jlfSQ5nuyTFQNuuIhE/O5QbVqHC6d4Y91U5JQisSLHLEgB/BAgMBAAECgYADtbrbsgfu6K7DgEpowJXjVNqDybLD1my7Em5WfUkUc6R+KKf3EI0w/3JTsWNWewYRzf26XadiE4F+IOekUHDcsl448FVd2D6ch1ea62SnpEYSKD2IOQ91bW32i2U5xQXdvms8UY6HcsCeNkEvsjfC/JiB6WJtp3INq0crAlebiQJBAPrwqtS7lMiieJ/uvVMJxkMLL8CDLvI+4/nRTFAKrI7I2x5rkjvZPDxFRHHlwiZSAoH4dIl2pm93tDdx/AvKpScCQQDxwGRxKvzfLp0VH9jSm/IA1RtbJLDvBlk4KSSrcmlUiYZaWfG4VXMYVMLJb4+v+M/ww08clMpQocPfAsAzULTXAkEA8AIjwhgvc75BlOYo2jUtFY6re3t8+WFBdvzB+oRbCq39NZk5YliiDhtKHY3dJf2mPF1ASQHcqhxZl/ZDVZvaXQJBAJuNWNO8flM40hg6krAJabEBboW52SMjqZrKVm7+wimEB+/w+ejLCrC4MVGduA3Zgir/8NKKJpe1TqwbQAKExqcCQQCq6PqG3UssJnpF56sFzPETJ7Sre7uKaeVYN/R8YQrvOjW7OdX/VWGhaxKvCJvySaDNh3VEP4UrF5EpnMW00BGc";

    @BeforeAll
    public void init() {
        System.out.printf("\npublicKey:\t%s\nprivateKey:\t%s\n\n", publicKey, privateKey);
    }

    @Test
    public void testSmallData() throws Throwable {
        byte[] encode = RsaCodec.encode(data.getBytes(), publicKey);
        byte[] decode = RsaCodec.decode(encode, privateKey);
        String output = new String(decode);
        System.out.printf("\nin:\t\t%s\nout:\t%s\n\n", data, output);
        Assertions.assertEquals(data, output);
    }

    @Test
    public void testLargeData() throws Throwable {
        byte[] encode = RsaCodec.encode(largeData.getBytes(), publicKey);
        byte[] decode = RsaCodec.decode(encode, privateKey);
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

}
