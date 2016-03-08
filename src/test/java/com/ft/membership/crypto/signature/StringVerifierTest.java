package com.ft.membership.crypto.signature;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

public class StringVerifierTest {
    private StringVerifier stringVerifier;
    private Verifier mockVerifier;

    public StringVerifierTest() {
        mockVerifier = mock(Verifier.class);
        stringVerifier = new StringVerifier(mockVerifier);
    }

    @Test
    public void shouldUTF8EncodeStringAndVerifyAgainstBase64DecodedSignature() throws UnsupportedEncodingException {
        final String signature = "111222333444";
        final String stringToSign = "ユニコード文字列は署名します"; //using unicode to check UTF-8 encoding

        when(mockVerifier.isSignatureValid(stringToSign.getBytes("UTF-8"), Encoder.getBase64DecodedBytes(signature).get()))
                .thenReturn(true);

        assertThat(stringVerifier.isSignatureValid(stringToSign, signature), equalTo(true));
    }

    @Test
    public void shouldUTF8EncodeStringAndFailToVerifyAgainstInvalidBase64DecodedSignature()
            throws UnsupportedEncodingException {
        final String invalidSignature = "111222333444";
        final String stringToSign = "ユニコード文字列は署名します"; //using unicode to check UTF-8 encoding

        when(mockVerifier.isSignatureValid(stringToSign.getBytes("UTF-8"), Encoder.getBase64DecodedBytes(invalidSignature).get()))
                .thenReturn(false);

        assertThat(stringVerifier.isSignatureValid(stringToSign, invalidSignature), equalTo(false));
    }
}