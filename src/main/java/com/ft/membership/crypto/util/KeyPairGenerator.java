package com.ft.membership.crypto.util;

import com.ft.membership.crypto.signature.Encoder;
import sun.security.ec.ECKeyPairGenerator;

import java.security.KeyPair;

/**
 * A utility class to generate secure public-private key pairs.
 *
 * @since 0.1
 */
public class KeyPairGenerator {

    ECKeyPairGenerator ecKeyPairGenerator;
    KeyPair keyPair;

    public KeyPairGenerator() {
        ecKeyPairGenerator = new ECKeyPairGenerator();
        keyPair = ecKeyPairGenerator.generateKeyPair();
    }

    /**
     * Get a base64 encoded String representation of the private key
     *
     * @return private key
     */
    public String getBase64EncodedPrivateKey() {
        return Encoder.getBase64EncodedString(keyPair.getPrivate().getEncoded());
    }

    /**
     * Get a base64 encoded String representation of the public key
     *
     * @return public key
     */
    public String getBase64EncodedPublicKey() {
        return Encoder.getBase64EncodedString(keyPair.getPublic().getEncoded());
    }
}
