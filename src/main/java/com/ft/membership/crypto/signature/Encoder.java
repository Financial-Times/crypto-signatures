package com.ft.membership.crypto.signature;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public class Encoder {

    private static final Base64.Encoder BASE_64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE_64_DECODER = Base64.getUrlDecoder();

    /**
     * Get Base64 encoded String of a byte array in UTF-8 charset
     *
     * @param bytes
     * @return
     */
    public static String getBase64EncodedString(final byte[] bytes) {

        return BASE_64_ENCODER.encodeToString(bytes);
    }

    /**
     * Get byte array in UTF-8 charset from Base64 encoded string
     *
     * @param encodedString
     * @return
     */
    public static Optional<byte[]> getBase64DecodedBytes(final String encodedString) {

        try {
            return Optional.of(BASE_64_DECODER.decode(encodedString));
        } catch(IllegalArgumentException e) {
            // We do not want a RuntimeException to be thrown when the string passed is not in valid Base64 scheme
            // as bad input is possible to the lib methods.
            return Optional.empty();
        }
    }
}
