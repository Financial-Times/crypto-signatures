package com.ft.membership.crypto.signature;

import com.ft.membership.crypto.util.KeyPairGenerator;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class SignerTest {

    private static String privateKey;
    private static String publicKey;

    @BeforeClass
    public static void setup() {

        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        privateKey = keyPairGenerator.getBase64EncodedPrivateKey();
        publicKey = keyPairGenerator.getBase64EncodedPublicKey();
    }

    @Test
    public void testValidSignatureIsVerifiedSuccessfully() throws Exception {

        Signer signer = new Signer(publicKey, privateKey);
        String testString = "foo";
        byte[] signedBytes = signer.signBytes(testString.getBytes());

        Assert.assertTrue(signer.isSignatureValid(testString.getBytes(), signedBytes));
    }

    @Test
    public void testTamperedSignatureIsNotVerifiedSuccessfully() throws Exception {

        Signer signer = new Signer(publicKey, privateKey);
        String testString = "foo";
        byte[] signedBytes = signer.signBytes(testString.getBytes());
        // tamper signed bytes
        signedBytes[0] = signedBytes[1];

        Assert.assertFalse(signer.isSignatureValid(testString.getBytes(), signedBytes));
    }

}