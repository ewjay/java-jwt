package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.json.simple.parser.JSONParser;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class VerifyJWTKeysTest {
    private static JSONParser jsonParser = new JSONParser();
    private KeyJar aliceKeyJar;
    private KeyJar bobKeyJar;
    private String jwt_a;
    private String jwt_a_with_kid;

    private String jwt_b;
    private String jwt_b_with_kid;
    private String jwt_b_with_abcedf_kid;

    private static final String JWK1STRING = "{\"keys\": [" +
        "{\"n\":\"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz" +
        "5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv" +
        "3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lw" +
        "OYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w" +
        "\"," +
        "\"e\": \"AQAB\", " +
        "\"kty\": \"RSA\", " +
        "\"kid\": \"rsa1\"}," +
        "{\"k\":\"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE\"," +
        "\"kty\": \"oct\"}," +
        "]}";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        String mkey = "[{\"type\": \"RSA\", \"use\": [\"sig\"]},{\"type\": \"RSA\", \"use\": [\"sig\"]},{\"type\": \"RSA\", \"use\": [\"sig\"]}]";
        System.out.println(mkey);
        String skey = "[{\"type\": \"RSA\", \"use\": [\"sig\"]}]";
        ;
        List<Object> mkeyJson = (List<Object>) jsonParser.parse(mkey);
        List<Object> skeyJson = (List<Object>) jsonParser.parse(skey);

        aliceKeyJar = KeyJar.buildKeyJar(mkeyJson, "", null, null);
        bobKeyJar = KeyJar.buildKeyJar(skeyJson, "", null, null);

        aliceKeyJar.setBundle("Alice", aliceKeyJar.getBundle(""));
        bobKeyJar.setBundle("Bob", bobKeyJar.getBundle(""));
//        Map<String, Object> tes = (Map<String, List<Map<String, Object>.)bobKeyJar.exportJwks(false, "Bob");
        aliceKeyJar.importJwks(bobKeyJar.exportJwks(false, "Bob"), "Bob");
//        aliceKeyJar.importJwksAsJson(bobKeyJar.exportJwksAsJson(false, "Bob"), "Bob");
        bobKeyJar.importJwks(aliceKeyJar.exportJwks(false, "Alice"), "Alice");
//        bobKeyJar.importJwksAsJson(aliceKeyJar.exportJwksAsJson(false, "Alice"), "Alice");


        Key aliceSignKey = aliceKeyJar.getSigningKey("rsa", "Alice", null, null).get(0);
        Algorithm aliceAlgorithm = Algorithm.RSA256((RSAPublicKey) aliceSignKey.getKey(false),
            (RSAPrivateKey) aliceKeyJar.getSigningKey("rsa", "Alice", null, null).get(0).getKey(true));
        jwt_a = JWT.create().withClaim("aud", "Bob")
            .withClaim("iss", "Alice").sign(aliceAlgorithm);
        jwt_a_with_kid = JWT.create().withClaim("aud", "Bob")
            .withClaim("iss", "Alice")
            .withKeyId(aliceSignKey.getKid())
            .sign(aliceAlgorithm);
        System.out.println(jwt_a);
        System.out.println(jwt_a_with_kid);


        Key bobSignKey = bobKeyJar.getSigningKey("rsa", "Bob", null, null).get(0);
        Algorithm bobAlgorithm = Algorithm.RSA256((RSAPublicKey) bobSignKey.getKey(false),
            (RSAPrivateKey) bobKeyJar.getSigningKey("rsa", "Bob", null, null).get(0).getKey(true));

        jwt_b = JWT.create().withClaim("aud", "Alice")
            .withClaim("iss", "Bob").sign(bobAlgorithm);
        jwt_b_with_kid = JWT.create().withClaim("aud", "Alice")
            .withClaim("iss", "Bob")
            .withKeyId(bobSignKey.getKid())
            .sign(bobAlgorithm);
        jwt_b_with_abcedf_kid = JWT.create().withClaim("aud", "Alice")
            .withClaim("iss", "Bob")
            .withKeyId("abcdef")
            .sign(bobAlgorithm);
        System.out.println(jwt_b);
        System.out.println(jwt_b_with_kid);


        System.out.println("alice : " + aliceKeyJar.exportJwks(true, "Alice"));

        System.out.println("bob : " + bobKeyJar.exportJwks(true, "Bob"));
        System.out.println("<==== END SETUP ====>");

    }

    @Test
    public void testNoKidMultipleKeys() throws Exception {
        List<Key> keys = bobKeyJar.getJWTVerifyKeys(jwt_a, null, null, false, false);
        Assert.assertEquals(0, keys.size());
        List<Key> keys1 = bobKeyJar.getJWTVerifyKeys(jwt_a, null, null, true, false);
        Assert.assertEquals(3, keys1.size());
    }


    @Test
    public void testNoKidSingleKeys() throws Exception {
        List<Key> keys = aliceKeyJar.getJWTVerifyKeys(jwt_b, null, null, false, false);
        Assert.assertEquals(1, keys.size());
    }


    @Test
    public void testNoKidMultipleKeysNoKidIssuer() throws Exception {
        List<Key> aliceKeys = aliceKeyJar.getVerifyKey("RSA", "Alice", null, null);

        Set<String> aliceKids = new HashSet<>();
        for (Key key : aliceKeys) {
            aliceKids.add(key.getKid());
        }

        Map<String, List<String>> noKidIssuer = new HashMap<>();
        noKidIssuer.put("Alice", Arrays.asList(aliceKids.toArray(new String[0])));

        List<Key> keys = bobKeyJar.getJWTVerifyKeys(jwt_a, null, noKidIssuer, false, false);
        Assert.assertEquals(3, keys.size());

        Set<String> kids = new HashSet<>();
        for (Key key : keys) {
            kids.add(key.getKid());
        }
        Assert.assertTrue(aliceKids.equals(kids));
    }

    @Test
    public void testMatchingKid() throws Exception {
        List<Key> keys = aliceKeyJar.getJWTVerifyKeys(jwt_b_with_kid, null, null, false, false);
        Assert.assertEquals(1, keys.size());

    }


    @Test
    public void testNoMatchingKid() throws Exception {
        List<Key> keys = aliceKeyJar.getJWTVerifyKeys(jwt_b_with_abcedf_kid, null, null, false, false);
        Assert.assertEquals(0, keys.size());
    }


    @Test
    public void testAud() throws Exception {

        aliceKeyJar.importJwksAsJson(JWK1STRING, "D");
        bobKeyJar.importJwksAsJson(JWK1STRING, "D");


        SYMKey signKey = (SYMKey) aliceKeyJar.getSigningKey("oct", "D", null, null).get(0);
        Algorithm algorithm = Algorithm.HMAC256(signKey.getKey(true).getEncoded());

        String jws = JWT.create().withClaim("aud", "A")
            .withClaim("iss", "D").sign(algorithm);

        Map<String, List<String>> noKidIssuer = new HashMap<>();
        noKidIssuer.put("D", Collections.emptyList());

        List<Key> keys = bobKeyJar.getJWTVerifyKeys(jws, null, noKidIssuer, false, false);

        Assert.assertEquals(1, keys.size());


    }


}