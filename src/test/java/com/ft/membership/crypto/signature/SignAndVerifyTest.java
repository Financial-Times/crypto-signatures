package com.ft.membership.crypto.signature;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Test;

import com.ft.membership.crypto.util.KeyPairGenerator;

public class SignAndVerifyTest {

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
        Signer signer = new Signer(privateKey);
        String testString = "foo";
        byte[] signature = signer.signBytes(testString.getBytes());

        Verifier verifier = new Verifier(publicKey);
        assertTrue(verifier.isSignatureValid(testString.getBytes(), signature));
    }

    @Test
    public void testTamperedSignatureIsNotVerifiedSuccessfully() throws Exception {
        Signer signer = new Signer(privateKey);
        String testString = "foo";
        byte[] signature = signer.signBytes(testString.getBytes());
        // tamper signature
        signature[0] = (byte) (signature[0] ^ 0x01);

        Verifier verifier = new Verifier(publicKey);
        assertFalse(verifier.isSignatureValid(testString.getBytes(), signature));
    }


}