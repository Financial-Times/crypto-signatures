package com.ft.membership.crypto.signature;

public class Config {
    private static final String SECURITY_PROVIDER = "SunEC";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String KEY_ALGORITHM = "EC";

    public static String getSecurityProvider() {
        return SECURITY_PROVIDER;
    }

    public static String getSignatureAlgorithm() {
        return SIGNATURE_ALGORITHM;
    }

    public static String getKeyAlgorithm() {
        return KEY_ALGORITHM;
    }
}
