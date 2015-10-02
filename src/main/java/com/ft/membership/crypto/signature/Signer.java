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
import java.util.Optional;
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
     * Sign the bytes provided as argument and return the signature as string
     *
     * @param bytes - byte array to sign
     * @return signature as a based64 encoded String
     */
    public String signBytes(final byte[] bytes) {

        final Operation resultOperation = Operation.resultOperation("signBytes")
                                                    .with("transaction_id", UUID.randomUUID())
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
            final String signedDataAsString = Encoder.getBase64EncodedString(signedBytes);

            final String resultString = String.format("{\"data\": \"%s\", \"signature\": \"%s\"}",
                                        new String(bytes),
                                        signedDataAsString);
            resultOperation.wasSuccessful().yielding("signBytesResult", resultString).log();

            return signedDataAsString;
        } catch (SignatureException e) {
            resultOperation.wasFailure().throwingException(e).log();
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the signature for a given byte array
     *
     * @param bytes - byte array of the data whose signature is to be verified
     * @param signature - base64 encoded signature of the bytes
     * @return boolean representing the validity of the signature
     */
    public boolean isSignatureValid(final byte[] bytes, final String signature) {

        final Operation resultOperation = Operation.resultOperation("isSignatureValid")
                                                    .with("transaction_id", UUID.randomUUID())
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
            final Optional<byte[]> base64DecodedBytes = Encoder.getBase64DecodedBytes(signature);
            valid = ellipticCurveDSA.verify(base64DecodedBytes.get());
        } catch (SignatureException e) {
            resultOperation.wasFailure().throwingException(e).log();
        }

        String resultString = String.format("{\"data\": \"%s\", \"signature\": \"%s\", \"isValid\": \"%b\"}",
                                            new String(bytes),
                                            signature,
                                            valid);
        resultOperation.wasSuccessful().yielding("isSignatureValidResult", resultString).log();
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
