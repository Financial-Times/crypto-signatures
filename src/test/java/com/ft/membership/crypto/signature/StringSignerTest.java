package com.ft.membership.crypto.signature;

import org.junit.Test;

import java.io.UnsupportedEncodingException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class StringSignerTest {
    private StringSigner stringSigner;
    private Signer mockSigner;

    public StringSignerTest() {
        mockSigner = mock(Signer.class);
        stringSigner = new StringSigner(mockSigner);
    }

    @Test
    public void shouldUTF8EncodeStringAndReturnSignatureAsUrlSafeBase64() throws UnsupportedEncodingException {
        final String signature = "Signature as a string";
        final String stringToSign = "ユニコード文字列は署名します"; //using unicode to check UTF-8 encoding

        when(mockSigner.signBytes(stringToSign.getBytes("UTF-8")))
                .thenReturn(signature.getBytes("UTF-8"));

        assertThat(stringSigner.signString(stringToSign), equalTo(signature));
    }

    @Test
    public void shouldUTF8EncodeStringAndVerifyAgainstBase64DecodedSignature() throws UnsupportedEncodingException {
        final String signature = "Signature as a string";
        final String stringToSign = "ユニコード文字列は署名します"; //using unicode to check UTF-8 encoding

        when(mockSigner.isSignatureValid(stringToSign.getBytes("UTF-8"), signature.getBytes("UTF-8")))
                .thenReturn(true);

        assertThat(stringSigner.isSignatureValid(stringToSign, signature), equalTo(true));
    }

    @Test
    public void shouldUTF8EncodeStringAndFailToVerifyAgainstInvalidBase64DecodedSignature() throws UnsupportedEncodingException {
        final String invalidSignature = "Invalid signature as a string";
        final String stringToSign = "ユニコード文字列は署名します"; //using unicode to check UTF-8 encoding

        when(mockSigner.isSignatureValid(stringToSign.getBytes("UTF-8"), invalidSignature.getBytes("UTF-8")))
                .thenReturn(false);

        assertThat(stringSigner.isSignatureValid(stringToSign, invalidSignature), equalTo(false));
    }
}