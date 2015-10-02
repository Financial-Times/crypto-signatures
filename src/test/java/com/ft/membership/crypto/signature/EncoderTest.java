package com.ft.membership.crypto.signature;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.IntStream;

public class EncoderTest {

    @Test
    public void testGetBase64EncodedString() throws Exception {

        String testString = "foo";
        byte[] encodedBytes = Base64.getUrlEncoder().withoutPadding().encode(testString.getBytes());
        String expectedEncodedString = new String(encodedBytes, StandardCharsets.UTF_8);
        String actualEncodedString  = Encoder.getBase64EncodedString(testString.getBytes());

        Assert.assertEquals(expectedEncodedString, actualEncodedString);
    }

    @Test
    public void testGetBase64DecodedBytes() throws Exception {

        String testString = "foo";
        byte[] encodedBytes = Base64.getUrlEncoder().withoutPadding().encode(testString.getBytes());
        String encodedString = new String(encodedBytes, StandardCharsets.UTF_8);
        byte[] expectedDecodedBytes = Base64.getUrlDecoder().decode(encodedBytes);
        byte[] actualDecodedBytes = Encoder.getBase64DecodedBytes(encodedString).get();

        Assert.assertArrayEquals(expectedDecodedBytes, actualDecodedBytes);
    }

    @Test
    public void testEncodeThenDecode() throws Exception {

        String testString = "foo";
        String encodedString = Encoder.getBase64EncodedString(testString.getBytes());
        byte[] decodedBytes = Encoder.getBase64DecodedBytes(encodedString).get();

        Assert.assertEquals(testString, new String(decodedBytes, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncodingAndDecodingOfStringWithLatinChars() throws Exception {

        String testString = "êfooñbar";
        String encodedString = Encoder.getBase64EncodedString(testString.getBytes());
        byte[] decodedBytes = Encoder.getBase64DecodedBytes(encodedString).get();

        Assert.assertEquals(testString, new String(decodedBytes, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncodingAndDecodingOfAREALLLLLLLYYYYYYLOOOOOONGString() throws Exception {

        StringBuilder stringBuilder = new StringBuilder();

        IntStream.iterate(0, i -> i + 2)
                .limit(10000)
                .forEach(number -> {
                    char[] ch = Character.toChars(number);
                    stringBuilder.append(new String(ch));
                });

        String testString = stringBuilder.toString();
        String encodedString = Encoder.getBase64EncodedString(testString.getBytes());
        byte[] decodedBytes = Encoder.getBase64DecodedBytes(encodedString).get();

        Assert.assertEquals(testString, new String(decodedBytes, StandardCharsets.UTF_8));
    }

}