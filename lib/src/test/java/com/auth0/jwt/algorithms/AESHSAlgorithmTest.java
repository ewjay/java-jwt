package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.msg.RSAKey;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class AESHSAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void shouldFailWithNullCipherParams() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The cipher param cannot be null");
        Algorithm encAlg = Algorithm.A128CBC_HS256(null);
    }

    @Test
    public void shouldFailWithBadKeyLength_A128CBC_HS256() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The key size is invalid for the algorithm A128CBC-HS256. Expected size : 128 Actual : 80");
        byte[] encKey = new byte[10];
        CipherParams cipherParams = new CipherParams(encKey, null);
        Algorithm encAlg = Algorithm.A128CBC_HS256(cipherParams);
    }

    @Test
    public void shouldFailWithBadKeyLength_A192CBC_HS384() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The key size is invalid for the algorithm A192CBC-HS384. Expected size : 192 Actual : 80");
        byte[] encKey = new byte[10];
        CipherParams cipherParams = new CipherParams(encKey, null);
        Algorithm encAlg = Algorithm.A192CBC_HS384(cipherParams);
    }


    @Test
    public void shouldFailWithBadMacKeyLength() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The mac key size is invalid for the algorithm A128CBC-HS256. Expected size : 128 Actual : 0");
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[0];
        byte[] iv = new byte[16];
        CipherParams cipherParams = new CipherParams(encKey, macKey, iv);
        Algorithm encAlg = Algorithm.A128CBC_HS256(cipherParams);
    }


    @Test
    public void shouldFailWithBadIVLength() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The IV size is invalid for the algorithm A128CBC-HS256. Expected size : 128 Actual : 0");
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];
        byte[] iv = new byte[0];
        CipherParams cipherParams = new CipherParams(encKey, macKey, iv);
        Algorithm encAlg = Algorithm.A128CBC_HS256(cipherParams);
    }

    @Test
    public void shouldFailWithBadTag() throws Exception {
        exception.expect(DecryptionException.class);
        CipherParams cipherParams = CipherParams.getInstance("A128CBC-HS256");
        Algorithm encAlg2 = Algorithm.A128CBC_HS256(cipherParams);
        byte[] content = "Test".getBytes();
        byte[] tag = "testTag".getBytes();
        AuthenticatedCipherText authenticatedCipherText = encAlg2.encrypt(content, tag);
        byte[] plainText = encAlg2.decrypt(authenticatedCipherText.getCipherText(), authenticatedCipherText.getTag(), "dd".getBytes());
        String text = new String(plainText);
        System.out.println(text);

    }

}
