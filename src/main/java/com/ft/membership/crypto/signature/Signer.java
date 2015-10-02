package com.ft.membership.crypto.signature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * This class provide methods to create and verify cryptographic signatures.
 *
 * @since 0.1
 */
public class Signer {

    private static final String SECURITY_PROVIDER_SUN_EC = "SunEC";
    private static final String ALGORITHM = "SHA256withECDSA";

    private final KeyPair keyPair;

    public Signer(final String base64EncodedPublicKey,
                  final String base64EncodedPrivateKey) {

        this.keyPair = createKeyPair(base64EncodedPublicKey, base64EncodedPrivateKey);
    }

    /**
     * Sign the bytes provided as argument and return the signed bytes
     *
     * @param bytes - byte array to sign
     * @return signed byte array
     */
    public byte[] signBytes(final byte[] bytes) {

        Signature ellipticCurveDSA;

        try {
            ellipticCurveDSA = Signature.getInstance(ALGORITHM, SECURITY_PROVIDER_SUN_EC);
            ellipticCurveDSA.initSign(keyPair.getPrivate());
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try {
            ellipticCurveDSA.update(bytes);
            return ellipticCurveDSA.sign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the signature for a given byte array
     *
     * @param bytes - byte array of the data whose signature is to be verified
     * @param signature - signature of bytes
     * @return boolean representing the validity of the signature
     */
    public boolean isSignatureValid(final byte[] bytes, final byte[] signature) {

        Signature ellipticCurveDSA;

        try {
            ellipticCurveDSA = Signature.getInstance(ALGORITHM, SECURITY_PROVIDER_SUN_EC);
            ellipticCurveDSA.initVerify(keyPair.getPublic());
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        boolean valid = false;
        try {
            ellipticCurveDSA.update(bytes);
            valid = ellipticCurveDSA.verify(signature);
        } catch (SignatureException e) {
            // TODO: what useful thing can you do at this stage? The signature is in-valid, the method will return the
            // appropriate value. Any other useful action possible here?
        }
        return valid;

    }

    private KeyPair createKeyPair(final String base64EncodedPublicKey,
                                  final String base64EncodedPrivateKey) {

        byte[] publicKeyBytes = Encoder.getBase64DecodedBytes(base64EncodedPublicKey);
        byte[] privateKeyBytes = Encoder.getBase64DecodedBytes(base64EncodedPrivateKey);

        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC", SECURITY_PROVIDER_SUN_EC);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
