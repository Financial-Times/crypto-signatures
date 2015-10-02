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
        String signature = signer.signBytes(testString.getBytes());

        Assert.assertTrue(signer.isSignatureValid(testString.getBytes(), signature));
    }

    @Test
    public void testTamperedSignatureIsNotVerifiedSuccessfully() throws Exception {

        Signer signer = new Signer(publicKey, privateKey);
        String testString = "foo";
        String signature = signer.signBytes(testString.getBytes());
        // tamper signature
        char ch = signature.charAt(0);
        ch ++;
        signature = ch + signature.substring(1);

        Assert.assertFalse(signer.isSignatureValid(testString.getBytes(), signature));
    }

}