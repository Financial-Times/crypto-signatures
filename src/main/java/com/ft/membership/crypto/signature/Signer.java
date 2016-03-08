package com.ft.membership.crypto.signature;

/**
 * This class provide methods to create and verify cryptographic signatures.
 *
 * @since 0.1
 */
@Deprecated
public class Signer {

    private final SignerOnly signer;
    private final Verifier verifier;


    public Signer(final String base64EncodedPublicKey,
                  final String base64EncodedPrivateKey) {

        signer = new SignerOnly(base64EncodedPrivateKey);
        verifier = new Verifier(base64EncodedPublicKey);
    }

    public byte[] signBytes(final byte[] bytes) {
        return signer.signBytes(bytes);
    }

    public byte[] signBytes(final byte[] bytes, final String transactionId) {
        return signer.signBytes(bytes, transactionId);
    }

    public boolean isSignatureValid(final byte[] bytes, final byte[] signature) {
        return verifier.isSignatureValid(bytes, signature);
    }

    public boolean isSignatureValid(final byte[] bytes, final byte[] signature, String transactionId) {
        return verifier.isSignatureValid(bytes, signature, transactionId);
    }

    public SignerOnly getSigner() {
        return signer;
    }

    public Verifier getVerifier() {
        return verifier;
    }
}
