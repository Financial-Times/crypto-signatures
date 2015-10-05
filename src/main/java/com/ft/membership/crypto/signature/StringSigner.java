package com.ft.membership.crypto.signature;

import com.ft.membership.logging.Operation;
import com.google.common.base.Throwables;

import java.io.UnsupportedEncodingException;
import java.util.UUID;

/**
 * This class provide methods to create and verify cryptographic signatures for strings.
 *
 * @since 0.23.0
 */
public class StringSigner {
    private final Signer signer;

    public StringSigner(final String base64EncodedPublicKey, final String base64EncodedPrivateKey) {
        signer = new Signer(base64EncodedPublicKey, base64EncodedPrivateKey);
    }


    public StringSigner(final Signer signer) {
        this.signer = signer;
    }

    /**
     * Sign the UTF-8 encoding of the string provided as argument, and return the signature as a base64 encoded string.
     *
     * @param string - string to encode and sign
     * @return signature as a encoded as url safe base64 encoded string
     * @throws IllegalArgumentException, RuntimeException
     */
    public String signString(final String string) {
        return signString(string, UUID.randomUUID().toString());
    }

    /**
     * Sign the UTF-8 encoding of the string provided as argument, and return the signature as a base64 encoded string.
     *
     * @param string - string to encode and sign
     * @param transactionId - transaction id used for logging
     * @return signature as a encoded as url safe base64 encoded string
     * @throws IllegalArgumentException, RuntimeException, UnsupportedEncodingException
     */
    public String signString(final String string, final String transactionId) {
        final Operation operation = Operation.resultOperation("signString")
                .with("string_to_sign", string)
                .with("transaction_id", transactionId)
                .started(this);

        try {
            final byte[] stringAsBytes = string.getBytes("UTF-8");
            final byte[] signatureAsBytes = signer.signBytes(stringAsBytes);
            final String signatureString = new String(signatureAsBytes, "UTF-8");
            operation.wasSuccessful().log();
            return signatureString;
        } catch (Exception e) {
            operation.wasFailure().throwingException(e).log();
            throw Throwables.propagate(e);
        }
    }

    /**
     * Verifies the provided url safe base64 encoded signature for the UTF-8 encoding of the provided string
     *
     * @param string            - string whos UTF-8 encoding will be verified
     * @param signatureString   - string containing url safe base64 encoded signature
     * @return boolean representing the validity of the signature
     * @throws RuntimeException
     */
    public boolean isSignatureValid(final String string, final String signatureString) {
        return isSignatureValid(string, signatureString, UUID.randomUUID().toString());
    }

    /**
     * Verifies the provided url safe base64 encoded signature for the UTF-8 encoding of the provided string
     *
     * @param string            - string whos UTF-8 encoding will be verified
     * @param signatureString   - string containing url safe base64 encoded signature
     * @param transactionId - transaction id used for logging
     * @return boolean representing the validity of the signature
     * @throws RuntimeException
     */
    public boolean isSignatureValid(final String string, final String signatureString, final String transactionId) {
        final Operation operation = Operation.resultOperation("isSignatureValid")
                .with("string", string)
                .with("transaction_id", transactionId)
                .started(this);

        try {
            final byte[] stringAsBytes = string.getBytes("UTF-8");
            final byte[] signatureAsBytes = signatureString.getBytes("UTF-8");

            final boolean isValid = signer.isSignatureValid(stringAsBytes, signatureAsBytes);

            if(isValid) {
                operation.wasSuccessful().log();
            } else {
                operation.wasFailure().withDetail("signature_sting", signatureString).log();
            }

            return isValid;
        } catch (UnsupportedEncodingException e) {
            operation.wasFailure().throwingException(e).log();
            throw Throwables.propagate(e);
        }
    }
}