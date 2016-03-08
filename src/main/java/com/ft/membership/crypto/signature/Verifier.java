package com.ft.membership.crypto.signature;

import static com.ft.membership.crypto.signature.Signer.ALGORITHM;
import static com.ft.membership.crypto.signature.Signer.SECURITY_PROVIDER_SUN_EC;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import com.ft.membership.logging.Operation;

/**
 * This class provide methods to create and verify cryptographic signatures.
 *
 * @since 0.1
 */
public class Verifier {

    private final PublicKey publicKey;

    public Verifier(final PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Verifier(String base64EncodedPublicKey) {
        this.publicKey = createPublicKey(base64EncodedPublicKey);
    }

    /**
     * Verifies the signature for a given byte array
     *
     * @param bytes     - byte array of the data whose signature is to be verified
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
     * @param bytes         - byte array of the data whose signature is to be verified
     * @param signature     - byte array containing signature
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
            ellipticCurveDSA.initVerify(publicKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException e) {
            resultOperation.wasFailure().throwingException(e).log();
            throw new RuntimeException(e);
        }

        boolean isValid;
        try {
            ellipticCurveDSA.update(bytes);
            isValid = ellipticCurveDSA.verify(signature);
        } catch (SignatureException e) {
            resultOperation
                    .wasFailure()
                    .withDetail("signature_bytes", Encoder.getBase64EncodedString(bytes))
                    .throwingException(e)
                    .log();
            return false;
        }

        resultOperation.wasSuccessful().log();
        return isValid;
    }

    private PublicKey createPublicKey(final String base64EncodedPublicKey) {

        byte[] publicKeyBytes = Encoder.getBase64DecodedBytes(base64EncodedPublicKey)
                .orElseThrow(RuntimeException::new);

        final KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC", SECURITY_PROVIDER_SUN_EC);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            return publicKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

}
