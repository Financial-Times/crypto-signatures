package com.ft.membership.crypto.signature;

/**
 * This class provide methods to create and verify cryptographic signatures for strings.
 *
 * @since 0.23.0
 */
@Deprecated
public class StringSigner {
    private final StringSignerOnly stringSigner;
    private final StringVerifier stringVerifier;

    public StringSigner(final String base64EncodedPublicKey, final String base64EncodedPrivateKey) {
        stringSigner = new StringSignerOnly(new SignerOnly(base64EncodedPrivateKey));
        stringVerifier = new StringVerifier(new Verifier(base64EncodedPublicKey));
    }

    public StringSigner(final Signer signer) {
        this.stringSigner = new StringSignerOnly(signer.getSigner());
        this.stringVerifier = new StringVerifier(signer.getVerifier());
    }

    public String signString(final String string) {
        return stringSigner.signString(string);
    }

    public String signString(final String string, final String transactionId) {
        return stringSigner.signString(string, transactionId);
    }

    public boolean isSignatureValid(final String string, final String signatureString) {
        return stringVerifier.isSignatureValid(string, signatureString);
    }

    public boolean isSignatureValid(final String string, final String signatureString, final String transactionId) {
        return stringVerifier.isSignatureValid(string, signatureString, transactionId);
    }
}