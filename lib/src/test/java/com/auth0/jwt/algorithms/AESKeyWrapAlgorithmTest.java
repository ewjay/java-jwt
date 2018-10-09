package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.SecureRandom;
import java.util.Arrays;

public class AESKeyWrapAlgorithmTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void shouldFailWithNullKek() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Keywrap encryption key cannot be null");
        Algorithm algorithm = Algorithm.AES128Keywrap(null);
    }

    @Test
    public void shouldFailWithInvalidKekLen_A128() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Invald keywrap key length for algorithm A128KW. Expected 16 Actual 10");
        Algorithm algorithm = Algorithm.AES128Keywrap(new byte[10]);
    }

    @Test
    public void shouldFailWithInvalidKekLen_A192() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Invald keywrap key length for algorithm A192KW. Expected 24 Actual 10");
        Algorithm algorithm = Algorithm.AES192Keywrap(new byte[10]);
    }

    @Test
    public void shouldFailWithInvalidKekBlockLength() throws Exception {
        exception.expect(EncryptionException.class);
        byte[] kek = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(kek);
        Algorithm algorithm = Algorithm.AES128Keywrap(kek);
        byte[] wrappedKey = algorithm.wrap("hello".getBytes());
        secureRandom.nextBytes(kek);
        Algorithm algorithm2 = Algorithm.AES128Keywrap(kek);

        byte[] unwrappedKey = algorithm2.unwrap(wrappedKey);
    }

    @Test
    public void shouldFailWithInvalidKek() throws Exception {
        exception.expect(DecryptionException.class);
        byte[] kek = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(kek);
        Algorithm algorithm = Algorithm.AES128Keywrap(kek);
        byte[] wrappedKey = algorithm.wrap("helllllo".getBytes());
        secureRandom.nextBytes(kek);
        Algorithm algorithm2 = Algorithm.AES128Keywrap(kek);

        byte[] unwrappedKey = algorithm2.unwrap(wrappedKey);
    }

    @Test
    public void shouldPassWrapUnwrap() throws Exception {
        byte[] kek = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(kek);
        Algorithm algorithm = Algorithm.AES128Keywrap(kek);
        byte[] content = "helllllo".getBytes();
        byte[] wrappedKey = algorithm.wrap(content);
        byte[] unwrappedKey = algorithm.unwrap(wrappedKey);
        Assert.assertTrue(Arrays.equals(content, unwrappedKey));
    }

}
