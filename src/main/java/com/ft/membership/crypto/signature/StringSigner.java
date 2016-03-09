package com.ft.membership.crypto.signature;

import java.security.PrivateKey;
import java.util.UUID;

import com.ft.membership.logging.Operation;
import com.google.common.base.Throwables;

/**
 * This class provide methods to create cryptographic signatures for strings.
 *
 * @since 0.26.0
 */
public class StringSigner {
    private final Signer signer;

    public StringSigner(final PrivateKey privateKey) {
        signer = new Signer(privateKey);
    }

    public StringSigner(final String base64EncodedPrivateKey) {
        signer = new Signer(base64EncodedPrivateKey);
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
     * @param string        - string to encode and sign
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
            final String signatureString = Encoder.getBase64EncodedString(signatureAsBytes);
            operation.wasSuccessful().log();
            return signatureString;
        } catch (Exception e) {
            operation.wasFailure().throwingException(e).log();
            throw Throwables.propagate(e);
        }
    }


}