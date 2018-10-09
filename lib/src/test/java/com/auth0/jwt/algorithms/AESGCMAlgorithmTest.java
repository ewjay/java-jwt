package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.interfaces.Claim;
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
import java.util.Map;

public class AESGCMAlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void shouldFailWithNullCipherParams() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The cipher param cannot be null");
        Algorithm encAlg = Algorithm.A128GCM(null);
    }

    @Test
    public void shouldFailWithBadKeyLength() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The key size is invalid for the algorithm A128GCM. Expected size : 128 Actual : 80");
        byte[] encKey = new byte[10];
        CipherParams cipherParams = new CipherParams(encKey, null);
        Algorithm encAlg = Algorithm.A128GCM(cipherParams);
    }

    @Test
    public void shouldFailWithBadIVLength() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The IV size is invalid for the algorithm A128GCM. Expected size : 96 Actual : 0");
        byte[] encKey = new byte[16];
        CipherParams cipherParams = new CipherParams(encKey, null);
        Algorithm encAlg = Algorithm.A128GCM(cipherParams);
    }

    @Test
    public void shouldFilaWithBadTag() throws Exception {
        exception.expect(DecryptionException.class);
        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        KeyPair keyPair2 = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey2 = (RSAPrivateCrtKey) keyPair2.getPrivate();
        RSAPublicKey rsaPublicKey2 = (RSAPublicKey) keyPair2.getPublic();

        Algorithm rsaAlg = Algorithm.RSAOAEP(rsaPublicKey, null);
        CipherParams cipherParams = CipherParams.getInstance("A128GCM");
        Algorithm encAlg = Algorithm.A128GCM(cipherParams);

        JWTCreator.Builder builder = JWT.create()
            .withClaim("first_name", "Bugs Bunny")
            .withClaim("last_name", "Bunny")
            .withAudience("Bob")
            .withIssuer("Mark")
            .withSubject("Alice")
            .withClaim("birthdate", "20180101");
        String jwe = builder.encrypt(rsaAlg, encAlg);
        System.out.println(jwe);


        Algorithm rsaAlg2 = Algorithm.RSAOAEP(null, rsaPrivateKey);
        DecodedJWT decodedJWT = JWT.decode(jwe);
        if(decodedJWT.isJWE()) {
            byte[] encryptedKey = Base64.decodeBase64(decodedJWT.getKey());
            byte[] iv = Base64.decodeBase64(decodedJWT.getIV());
            byte[] tag = Base64.decodeBase64(decodedJWT.getAuthenticationTag());
            byte[] headerBytes = decodedJWT.getHeader().getBytes("UTF-8");
            byte[] cipherText = Base64.decodeBase64(decodedJWT.getCipherText());
            byte[] decryptedKey = rsaAlg2.decrypt(encryptedKey);
            CipherParams cipherParams2 = new CipherParams(decryptedKey, iv);
            tag[0] = (byte) 0xFF;
            Algorithm encAlg2 = Algorithm.A128GCM(cipherParams2);
            byte[] plainText = encAlg2.decrypt(cipherText, tag, headerBytes);
        }
    }

    @Test
    public void shouldFilaWithBadAuthenticationText() throws Exception {
        exception.expect(DecryptionException.class);
        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        KeyPair keyPair2 = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey2 = (RSAPrivateCrtKey) keyPair2.getPrivate();
        RSAPublicKey rsaPublicKey2 = (RSAPublicKey) keyPair2.getPublic();

        Algorithm rsaAlg = Algorithm.RSAOAEP(rsaPublicKey, null);
        CipherParams cipherParams = CipherParams.getInstance("A128GCM");
        Algorithm encAlg = Algorithm.A128GCM(cipherParams);

        JWTCreator.Builder builder = JWT.create()
            .withClaim("first_name", "Bugs Bunny")
            .withClaim("last_name", "Bunny")
            .withAudience("Bob")
            .withIssuer("Mark")
            .withSubject("Alice")
            .withClaim("birthdate", "20180101");
        String jwe = builder.encrypt(rsaAlg, encAlg);
        System.out.println(jwe);


        Algorithm rsaAlg2 = Algorithm.RSAOAEP(null, rsaPrivateKey);
        DecodedJWT decodedJWT = JWT.decode(jwe);
        if(decodedJWT.isJWE()) {
            byte[] encryptedKey = Base64.decodeBase64(decodedJWT.getKey());
            byte[] iv = Base64.decodeBase64(decodedJWT.getIV());
            byte[] tag = Base64.decodeBase64(decodedJWT.getAuthenticationTag());
            byte[] headerBytes = decodedJWT.getHeader().getBytes("UTF-8");
            byte[] cipherText = Base64.decodeBase64(decodedJWT.getCipherText());
            byte[] decryptedKey = rsaAlg2.decrypt(encryptedKey);
            CipherParams cipherParams2 = new CipherParams(decryptedKey, iv);
            Algorithm encAlg2 = Algorithm.A128GCM(cipherParams2);
            byte[] plainText = encAlg2.decrypt(cipherText, tag, "test".getBytes());
        }

    }

    @Test
    public void testAESGCMEncrypt() throws Exception {
        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        KeyPair keyPair2 = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey2 = (RSAPrivateCrtKey) keyPair2.getPrivate();
        RSAPublicKey rsaPublicKey2 = (RSAPublicKey) keyPair2.getPublic();

        Algorithm rsaAlg = Algorithm.RSAOAEP(rsaPublicKey, null);
        CipherParams cipherParams = CipherParams.getInstance("A128GCM");
        Algorithm encAlg = Algorithm.A128GCM(cipherParams);

        JWTCreator.Builder builder = JWT.create()
            .withClaim("first_name", "Bugs Bunny")
            .withClaim("last_name", "Bunny")
            .withAudience("Bob")
            .withIssuer("Mark")
            .withSubject("Alice")
            .withClaim("birthdate", "20180101");
        String jwe = builder.encrypt(rsaAlg, encAlg);
        System.out.println(jwe);


        Algorithm rsaAlg2 = Algorithm.RSAOAEP(null, rsaPrivateKey);
        DecodedJWT decodedJWT = JWT.decode(jwe);
        if(decodedJWT.isJWE()) {
            byte[] encryptedKey = Base64.decodeBase64(decodedJWT.getKey());
            byte[] iv = Base64.decodeBase64(decodedJWT.getIV());
            byte[] tag = Base64.decodeBase64(decodedJWT.getAuthenticationTag());
            byte[] headerBytes = decodedJWT.getHeader().getBytes("UTF-8");
            byte[] cipherText = Base64.decodeBase64(decodedJWT.getCipherText());


            byte[] decryptedKey = rsaAlg2.decrypt(encryptedKey);
            CipherParams cipherParams2 = new CipherParams(decryptedKey, iv);
            Algorithm encAlg2 = Algorithm.A128GCM(cipherParams2);
            byte[] plainText = encAlg2.decrypt(cipherText, tag, headerBytes);
            String text = new String(plainText);
            System.out.println(text);


        }
        System.out.println("\n========================================\n");
        System.out.println(new String(Base64.decodeBase64(decodedJWT.getHeader())));

        System.out.println("\n========================================\n");

        decodedJWT.decrypt(Algorithm.RSAOAEP(null, rsaPrivateKey));
        System.out.println("\n========================================\n");


        DecodedJWT jwt = JWT.require(rsaAlg2).withIssuer("Mark").withAudience("Bob").withSubject("Alice")
            .build()
            .verify(jwe);
        Map<String, Claim> claims = jwt.getClaims();
        for (Map.Entry<String, Claim> entry : claims.entrySet()) {
            System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asString());
        }

        exception.expect(DecryptionException.class);
        DecodedJWT jwt2 = JWT.require(Algorithm.RSAOAEP(null, rsaPrivateKey2)).withIssuer("Mark").withAudience("Bob").withSubject("Alice")
            .build()
            .verify(jwe);

    }
}
