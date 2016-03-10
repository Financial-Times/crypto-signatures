package com.ft.membership.crypto.signature;

import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.util.Optional;
import java.util.UUID;

import com.ft.membership.logging.Operation;
import com.google.common.base.Throwables;

/**
 * This class provide methods to verify cryptographic signatures for strings.
 *
 * @since 0.26.0
 */
public class StringVerifier {
    private final Verifier verifier;

    public StringVerifier(final PublicKey publicKey) {
        verifier = new Verifier(publicKey);
    }

    public StringVerifier(final String base64EncodedPublicKey) {
        verifier = new Verifier(base64EncodedPublicKey);
    }

    public StringVerifier(final Verifier verifier) {
        this.verifier = verifier;
    }

    /**
     * Verifies the provided url safe base64 encoded signature for the UTF-8 encoding of the provided string
     *
     * @param string          - string whos UTF-8 encoding will be verified
     * @param signatureString - string containing url safe base64 encoded signature
     * @return boolean representing the validity of the signature
     * @throws RuntimeException
     */
    public boolean isSignatureValid(final String string, final String signatureString) {
        return isSignatureValid(string, signatureString, UUID.randomUUID().toString());
    }

    /**
     * Verifies the provided url safe base64 encoded signature for the UTF-8 encoding of the provided string
     *
     * @param string          - string whos UTF-8 encoding will be verified
     * @param signatureString - string containing url safe base64 encoded signature
     * @param transactionId   - transaction id used for logging
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
            final Optional<byte[]> signatureAsBytesOption = Encoder.getBase64DecodedBytes(signatureString);

            return signatureAsBytesOption.map((signatureAsBytes) -> {
                final boolean isValid = verifier.isSignatureValid(stringAsBytes, signatureAsBytes);

                if (isValid) {
                    operation.wasSuccessful().log();
                } else {
                    operation.wasFailure().withMessage("signature was invalid")
                            .withDetail("signature_string", signatureString).log();
                }

                return isValid;
            })
            .orElseGet(() -> {
                operation.wasFailure().withMessage("signature was not correctly base64 encoded")
                        .withDetail("signature_string", signatureString).log();
                return false;
            });
        } catch (UnsupportedEncodingException e) {
            operation.wasFailure().throwingException(e).log();
            throw Throwables.propagate(e);
        }
    }
}