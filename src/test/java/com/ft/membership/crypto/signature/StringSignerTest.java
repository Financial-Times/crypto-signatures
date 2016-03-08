package com.ft.membership.crypto.signature;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

public class StringSignerTest {
    private StringSigner stringSigner;
    private Signer mockSigner;

    public StringSignerTest() {
        mockSigner = mock(Signer.class);
        stringSigner = new StringSigner(mockSigner);
    }

    @Test
    public void shouldUTF8EncodeStringAndReturnSignatureAsUrlSafeBase64() throws UnsupportedEncodingException {
        final String signature = "111222333444";
        final String stringToSign = "ユニコード文字列は署名します"; //using unicode to check UTF-8 encoding

        when(mockSigner.signBytes(stringToSign.getBytes("UTF-8")))
                .thenReturn(Encoder.getBase64DecodedBytes(signature).get());

        assertThat(stringSigner.signString(stringToSign), equalTo(signature));
    }

}