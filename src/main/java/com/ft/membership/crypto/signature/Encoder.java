package com.ft.membership.crypto.signature;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Encoder {

    private static final Base64.Encoder BASE_64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE_64_DECODER = Base64.getUrlDecoder();

    public static String getBase64EncodedString(final byte[] bytes) {

        return new String(BASE_64_ENCODER.encode(bytes), StandardCharsets.UTF_8);
    }

    public static byte[] getBase64DecodedBytes(final String encodedString) {

        return BASE_64_DECODER.decode(encodedString.getBytes(StandardCharsets.UTF_8));
    }
}
