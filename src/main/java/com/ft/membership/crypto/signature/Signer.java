package com.ft.membership.crypto.signature;

import com.ft.membership.logging.Operation;

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
import java.util.UUID;

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
     * Sign the bytes provided as argument and return the signature as bytes
     *
     * @param bytes - byte array to sign
     * @return signature as byte array
     * @throws IllegalArgumentException, RuntimeException
     */
    public byte[] signBytes(final byte[] bytes) {
        return signBytes(bytes, UUID.randomUUID().toString());
    }

    /**
     * Sign the bytes provided as argument and return the signature as bytes
     *
     * @param bytes - byte array to sign
     * @param transactionId - transaction id used for logging
     * @return signature as byte array
     * @throws IllegalArgumentException, RuntimeException
     */
    public byte[] signBytes(final byte[] bytes, final String transactionId) {

        final Operation resultOperation = Operation.resultOperation("signBytes")
                                                    .with("transaction_id", transactionId)
                                                    .with("bytes", Encoder.getBase64EncodedString(bytes) )
                                                    .started(this);

        Signature ellipticCurveDSA;

        try {
            ellipticCurveDSA = Signature.getInstance(ALGORITHM, SECURITY_PROVIDER_SUN_EC);
            ellipticCurveDSA.initSign(keyPair.getPrivate());
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException e) {
            resultOperation.wasFailure().throwingException(e).log();
            throw new RuntimeException(e);
        }

        try {
            ellipticCurveDSA.update(bytes);
            final byte[] signedBytes = ellipticCurveDSA.sign();
            resultOperation.wasSuccessful().log();
            return signedBytes;
        } catch (SignatureException e) {
            resultOperation.wasFailure().throwingException(e).log();
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the signature for a given byte array
     *
     * @param bytes - byte array of the data whose signature is to be verified
     * @param signature - byte array containing the signature
     * @return boolean representing the validity of the signature
     * @throws RuntimeException
     */
    public boolean isSignatureValid(final byte[] bytes, final byte[] signature) {
        return isSignatureValid(bytes, signature, UUID.randomUUID().toString());
    }


    /**
     * Verifies the signature for a given byte array
     *
     * @param bytes - byte array of the data whose signature is to be verified
     * @param signature - byte array containing signature
     * @param transactionId - transaction id used for logging
     * @return boolean representing the validity of the signature
     * @throws RuntimeException
     */
    public boolean isSignatureValid(final byte[] bytes, final byte[] signature, String transactionId) {
        final Operation resultOperation = Operation.resultOperation("isSignatureValid")
                .with("transaction_id", transactionId)
                .started(this);

        Signature ellipticCurveDSA;

        try {
            ellipticCurveDSA = Signature.getInstance(ALGORITHM, SECURITY_PROVIDER_SUN_EC);
            ellipticCurveDSA.initVerify(keyPair.getPublic());
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException e) {
            resultOperation.wasFailure().throwingException(e).log();
            throw new RuntimeException(e);
        }

        boolean valid = false;
        try {
            ellipticCurveDSA.update(bytes);
            valid = ellipticCurveDSA.verify(signature);
        } catch (SignatureException e) {
            resultOperation
                .wasFailure()
                .withDetail("signature_bytes", Encoder.getBase64EncodedString(bytes))
                .throwingException(e)
                .log();
        }

        resultOperation.wasSuccessful().log();
        return valid;
    }

    private KeyPair createKeyPair(final String base64EncodedPublicKey,
                                  final String base64EncodedPrivateKey) {

        final Operation resultOperation = Operation.resultOperation("createKeyPair")
                                                    .with("transaction_id", UUID.randomUUID())
                                                    .started(this);

        byte[] publicKeyBytes = Encoder.getBase64DecodedBytes(base64EncodedPublicKey)
                                        .orElseThrow(RuntimeException::new);
        byte[] privateKeyBytes = Encoder.getBase64DecodedBytes(base64EncodedPrivateKey)
                                        .orElseThrow(RuntimeException::new);

        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC", SECURITY_PROVIDER_SUN_EC);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            final KeyPair keyPair = new KeyPair(publicKey, privateKey);
            resultOperation.wasSuccessful().log();
            return keyPair;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            resultOperation.wasFailure().throwingException(e).log();
            throw new RuntimeException(e);
        }
    }
}
