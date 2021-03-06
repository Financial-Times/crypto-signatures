package com.ft.membership.crypto.signature;

import com.ft.membership.logging.Operation;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.UUID;

/**
 * This class provide methods to create and verify cryptographic signatures.
 *
 * @since 0.26.0
 */
public class Signer {

    private final PrivateKey privateKey;

    public Signer(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public Signer(String base64EncodedPrivateKey) {
        this.privateKey = createPrivateKey(base64EncodedPrivateKey);
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
     * @param bytes         - byte array to sign
     * @param transactionId - transaction id used for logging
     * @return signature as byte array
     * @throws IllegalArgumentException, RuntimeException
     */
    public byte[] signBytes(final byte[] bytes, final String transactionId) {

        final Operation resultOperation = Operation.operation("signBytes")
                .with("transaction_id", transactionId)
                .with("bytes", Encoder.getBase64EncodedString(bytes))
                .started(this);

        Signature ellipticCurveDSA;

        try {
            ellipticCurveDSA = Signature.getInstance(Config.getSignatureAlgorithm());
            ellipticCurveDSA.initSign(privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
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

    private PrivateKey createPrivateKey(final String base64EncodedPrivateKey) {

        byte[] privateKeyBytes = Encoder.getBase64DecodedBytes(base64EncodedPrivateKey)
                .orElseThrow(RuntimeException::new);

        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(Config.getKeyAlgorithm());
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
