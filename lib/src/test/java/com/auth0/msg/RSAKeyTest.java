package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class RSAKeyTest {

    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
    private final String PUBLIC_CERT_FILE = "src/test/resources/cert.pem";
    private final String PUBLIC_N = "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7" +
        "pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq" +
        "4N8vh4LLMQwLR6zi6Jtu82nB5k8";
    private final String PUBLIC_E = "AQAB";
    private final String JWK = "{\"keys\": [{\"kty\": \"RSA\", \"use\": \"foo\", " +
        "\"e\": \"" +
        PUBLIC_E +
        "\", \"kid\": \"abc\",\"n\": \"" +
        PUBLIC_N +
        "\"}]}";
    private final String ECKEY = "{\"crv\": \"P-521\"," +
        "\"x\": \"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4q" +
        "UxcWceqwQGk\"," +
        "\"y\": \"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ub" +
        "mf63e3kyMj2\"," +
        "\"d\": \"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d5" +
        "3vM9mE15j2C\"}";
    private static JSONParser jsonParser = new JSONParser();

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testGenRSAKeys() {
        int[] keySizes = new int[]{1024, 2048, 3072, 4096};
        for (int keySize : keySizes) {
            KeyPair keyPair = RSAKey.generateRSAKeyPair(keySize);
            Assert.assertNotNull(keyPair);
            Assert.assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
            Assert.assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            Assert.assertEquals(rsaPrivateKey.getModulus().bitLength(), keySize);
            Assert.assertEquals(rsaPublicKey.getModulus().bitLength(), keySize);
        }
    }

    @Test
    public void testExtractRSAKeyFromCertFile() throws Exception {
        PublicKey publicKey = KeyUtils.getRSAKeyFromCertFile(PUBLIC_CERT_FILE);
        RSAKey key = RSAKey.loadKey(publicKey);
        Assert.assertEquals(key.getN(), Utils.bigIntToBase64url(((RSAPublicKey) publicKey).getModulus()));
    }

    @Test
    public void testKSpec() throws Exception, SerializationNotPossible {
        PublicKey publicKey = KeyUtils.getRSAKeyFromCertFile(PUBLIC_CERT_FILE);
        RSAKey rsaKey = RSAKey.loadKey(publicKey);
        Map<String, Object> jwk = rsaKey.serialize();
        JSONObject jsonJWK = (JSONObject) jsonParser.parse(JWK);
        Assert.assertEquals("RSA", jwk.get("kty"));
        Map<String, Object> keys = (Map<String, Object>)(((List)jsonJWK.get("keys")).get(0));
        Assert.assertEquals(keys.get("e"), jwk.get("e"));
        Assert.assertEquals(keys.get("n"), jwk.get("n"));
    }

    @Test
    public void testSerializeRSAPubKey() throws IOException, JWKException , SerializationNotPossible{
        PublicKey publicKey = KeyUtils.getRSAPublicKeyFromFile(PUBLIC_KEY_FILE);
        RSAKey rsaKey = RSAKey.loadKey(publicKey);
        Assert.assertEquals("", rsaKey.getD());
        Map<String, Object> serializedKey = rsaKey.serialize(false);
        RSAKey restoredKey = new RSAKey("", "", "", null, "", "", null,
            (String)serializedKey.get(("n")), (String)serializedKey.get("e"), null, null, null,
            null, null, null, null, null);
        Assert.assertEquals(rsaKey, restoredKey);
    }

    @Test
    public void testSerializeRSAPubKey2() throws IOException, JWKException , SerializationNotPossible{
        PublicKey publicKey = KeyUtils.getRSAPublicKeyFromFile(PUBLIC_KEY_FILE);
        RSAKey rsaKey = RSAKey.loadKey(publicKey);
        Assert.assertEquals("", rsaKey.getD());
        Map<String, Object> serializedKey = rsaKey.serialize(false);
        RSAKey restoredKey = RSAKey.publicKeyBuilder((String)serializedKey.get(("n")),
            (String)serializedKey.get(("e"))).build();
        RSAKey restoredKey1 = new RSAKey("", "", "", null, "", "", null,
            (String)serializedKey.get(("n")), (String)serializedKey.get("e"), null, null, null,
            null, null, null, null, null);
        Assert.assertEquals(rsaKey, restoredKey);
    }


    @Test
    public void testSerializeRSAPrivateKey() throws IOException, JWKException , SerializationNotPossible{
        PrivateKey privateKey = KeyUtils.getRSAPrivateKeyFromFile(PRIVATE_KEY_FILE);
        RSAKey rsaKey = RSAKey.loadKey(privateKey);
        Assert.assertFalse(Utils.isNullOrEmpty(rsaKey.getD()));
        Map<String, Object> serializedKey = rsaKey.serialize(true);
        RSAKey restoredKey = new RSAKey("", "", "", null, "", "", null,
            (String)serializedKey.get(("n")), (String)serializedKey.get("e"),
            (String)serializedKey.get("d"), (String)serializedKey.get("p"),
            (String)serializedKey.get("q"), (String)serializedKey.get("dp"),
            (String)serializedKey.get("dq"), (String)serializedKey.get("qi"),
            (List<Map<String, String>>)serializedKey.get("oth"), null);
        Assert.assertEquals(rsaKey, restoredKey);
    }

    @Test
    public void testSerializeRSAPrivateKey2() throws IOException, JWKException , SerializationNotPossible{
        PrivateKey privateKey = KeyUtils.getRSAPrivateKeyFromFile(PRIVATE_KEY_FILE);
        RSAKey rsaKey = RSAKey.loadKey(privateKey);
        Assert.assertFalse(Utils.isNullOrEmpty(rsaKey.getD()));
        Map<String, Object> serializedKey = rsaKey.serialize(true);
        RSAKey restoredKey = RSAKey.privateKeyBuilder(
            (String)serializedKey.get(("n")),
            (String)serializedKey.get(("e")),
            (String)serializedKey.get(("d")),
            (String)serializedKey.get(("p")),
            (String)serializedKey.get(("q")),
            (String)serializedKey.get(("dp")),
            (String)serializedKey.get(("dq")),
            (String)serializedKey.get(("qi")),
            (List<Map<String, String>>)serializedKey.get(("oth"))).build();

        Assert.assertEquals(rsaKey, restoredKey);
    }


    @Test
    public void testCompareRSA() throws Exception {
        RSAKey rsaKey1 = new RSAKey(KeyUtils.getRSAKeyFromCertFile(PUBLIC_CERT_FILE), "");
        RSAKey rsaKey2 = new RSAKey(KeyUtils.getRSAKeyFromCertFile(PUBLIC_CERT_FILE), "");
        Assert.assertEquals(rsaKey1, rsaKey2);
    }

    @Test
    public void testCompareRsaEC() throws Exception, ParseException, SerializationNotPossible {
        RSAKey rsaKey = new RSAKey(KeyUtils.getRSAKeyFromCertFile(PUBLIC_CERT_FILE), "");
        JSONObject ecObject = (JSONObject) jsonParser.parse(ECKEY);
        ECKey ecKey = new ECKey("", "", "", null,
            (String)ecObject.get("crv"), (String)ecObject.get("x"), (String)ecObject.get("y"),
            (String)ecObject.get("d"), null);
        Assert.assertNotNull(rsaKey);
        Assert.assertNotNull(ecKey);
        Assert.assertNotEquals(rsaKey, ecKey);
    }


    @Test
    public void testRsaPubKeyFromX509CertChain() throws Exception {
        final String[] cert = new String[] {
            "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDA" +
            "OBgNVBAgTB0JhdmFyaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZX" +
            "J0aWZpY2F0aW9uIEF1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNM" +
            "TUwNDE1MTQ1NjM4WhcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21i" +
            "SDE7MDkGA1UEAxMyQmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGU" +
            "wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99b" +
            "dzUUIhDZG34PQqcH89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3X" +
            "je8fu55Csh0JXNfoy29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisI" +
            "Vqur9aujYwdCoAZU8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT" +
            "/7vdgS/IYXFniPuUfblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQ" +
            "YDVR0OBBYEFOfg3f/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpM" +
            "AsGA1UdDwQEAwIDiDATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0" +
            "549hEHRQArJXs1im7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3" +
            "rDywi2a9GKzOFgrWpVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA" +
            "2sW5AhPiCr9dVnMn/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqW" +
            "SfPRBZV8htRIf0vTlGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="};

        RSAKey rsaKey = new RSAKey("", "", "", cert, "", "", null,
            "","","","","","","","",null, null);
        Assert.assertNotNull(rsaKey);
        Assert.assertTrue(rsaKey.key instanceof RSAPublicKey);

    }

    @Test
    public void testRsaPubKeyVerifyX509Thumbprint() throws Exception {
        final String[] cert = new String[] {
            "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDA" +
            "OBgNVBAgTB0JhdmFyaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZX" +
            "J0aWZpY2F0aW9uIEF1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNM" +
            "TUwNDE1MTQ1NjM4WhcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21i" +
            "SDE7MDkGA1UEAxMyQmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGU" +
            "wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99b" +
            "dzUUIhDZG34PQqcH89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3X" +
            "je8fu55Csh0JXNfoy29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisI" +
            "Vqur9aujYwdCoAZU8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT" +
            "/7vdgS/IYXFniPuUfblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQ" +
            "YDVR0OBBYEFOfg3f/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpM" +
            "AsGA1UdDwQEAwIDiDATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0" +
            "549hEHRQArJXs1im7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3" +
            "rDywi2a9GKzOFgrWpVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA" +
            "2sW5AhPiCr9dVnMn/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqW" +
            "SfPRBZV8htRIf0vTlGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="};

        RSAKey rsaKey = new RSAKey("", "", "", cert, "KvHXVspLmjWC6cPDIIVMHlJjN-c",
            "", null,"","","","","","","","",null, null);
        Assert.assertNotNull(rsaKey);
        Assert.assertTrue(rsaKey.key instanceof RSAPublicKey);
        exception.expect(DeserializationNotPossible.class);
        RSAKey badThumbprintKey = new RSAKey("", "", "", cert, "abcdefgh-c",
            "", null,"","","","","","","","",null, null);

    }

    @Test
    public void testBuilder() throws JWKException {
        final String[] cert = new String[] {
            "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDA" +
            "OBgNVBAgTB0JhdmFyaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZX" +
            "J0aWZpY2F0aW9uIEF1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNM" +
            "TUwNDE1MTQ1NjM4WhcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21i" +
            "SDE7MDkGA1UEAxMyQmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGU" +
            "wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99b" +
            "dzUUIhDZG34PQqcH89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3X" +
            "je8fu55Csh0JXNfoy29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisI" +
            "Vqur9aujYwdCoAZU8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT" +
            "/7vdgS/IYXFniPuUfblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQ" +
            "YDVR0OBBYEFOfg3f/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpM" +
            "AsGA1UdDwQEAwIDiDATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0" +
            "549hEHRQArJXs1im7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3" +
            "rDywi2a9GKzOFgrWpVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA" +
            "2sW5AhPiCr9dVnMn/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqW" +
            "SfPRBZV8htRIf0vTlGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="};

        RSAKey rsaKey = RSAKey.builder().setX5c(cert).setX5t("KvHXVspLmjWC6cPDIIVMHlJjN-c").build();
        Assert.assertNotNull(rsaKey);
        Assert.assertTrue(rsaKey.key instanceof RSAPublicKey);
        exception.expect(DeserializationNotPossible.class);
        RSAKey badThumbprintKey = RSAKey.builder()
            .setX5c(cert)
            .setX5t("abcdefgh-c-c")
            .build();
    }

    @Test
    public void testKeyBuilder() throws JWKException, ValueError {
        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        RSAKey privateKey = RSAKey.privateKeyBuilder(
            Utils.bigIntToBase64url(rsaPrivateKey.getModulus()),
            Utils.bigIntToBase64url(rsaPrivateKey.getPublicExponent()),
            Utils.bigIntToBase64url(rsaPrivateKey.getPrivateExponent()),
            Utils.bigIntToBase64url(rsaPrivateKey.getPrimeP()),
            Utils.bigIntToBase64url(rsaPrivateKey.getPrimeQ()),
            Utils.bigIntToBase64url(rsaPrivateKey.getPrimeExponentP()),
            Utils.bigIntToBase64url(rsaPrivateKey.getPrimeExponentQ()),
            Utils.bigIntToBase64url(rsaPrivateKey.getCrtCoefficient()),
            Collections.emptyList()
        ).build();

        RSAKey publicKey = RSAKey.publicKeyBuilder(
            Utils.bigIntToBase64url(rsaPublicKey.getModulus()),
            Utils.bigIntToBase64url(rsaPublicKey.getPublicExponent())
        ).build();

        Assert.assertNotNull(privateKey);
        Assert.assertNotNull(publicKey);
        Assert.assertTrue(privateKey.getKey(true) instanceof  RSAPrivateCrtKey);
        Assert.assertEquals(rsaPrivateKey, (RSAPrivateCrtKey)privateKey.getKey(true));
        Assert.assertEquals(rsaPublicKey, (RSAPublicKey)privateKey.getKey(false));
        Assert.assertTrue(publicKey.getKey(false) instanceof  RSAPublicKey);
        Assert.assertEquals(rsaPublicKey, (RSAPublicKey) publicKey.getKey(false));
    }

    @Test
    public void testKeyBuilder2() throws JWKException, ValueError, SerializationNotPossible {

        int[] keySizes = new int[] {
            1024, 2048, 4096
        };

        for(int keySize : keySizes) {
            for(int i = 0; i < 5; i++) {
                KeyPair keyPair = RSAKey.generateRSAKeyPair(keySize);
                RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
                RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

                RSAKey privateKey = RSAKey.builder()
                    .setN(Utils.bigIntToBase64url(rsaPrivateKey.getModulus()))
                    .setE(Utils.bigIntToBase64url(rsaPrivateKey.getPublicExponent()))
                    .setD(Utils.bigIntToBase64url(rsaPrivateKey.getPrivateExponent()))
                    .setP(Utils.bigIntToBase64url(rsaPrivateKey.getPrimeP()))
                    .setQ(Utils.bigIntToBase64url(rsaPrivateKey.getPrimeQ()))
                    .setDp(Utils.bigIntToBase64url(rsaPrivateKey.getPrimeExponentP()))
                    .setDq(Utils.bigIntToBase64url(rsaPrivateKey.getPrimeExponentQ()))
                    .setQi(Utils.bigIntToBase64url(rsaPrivateKey.getCrtCoefficient())).build();

                Assert.assertEquals(privateKey.getN(), Utils.bigIntToBase64url(rsaPrivateKey.getModulus()));
                Assert.assertEquals(privateKey.getE(), Utils.bigIntToBase64url(rsaPrivateKey.getPublicExponent()));
                Assert.assertEquals(privateKey.getD(), Utils.bigIntToBase64url(rsaPrivateKey.getPrivateExponent()));
                Assert.assertEquals(privateKey.getP(), Utils.bigIntToBase64url(rsaPrivateKey.getPrimeP()));
                Assert.assertEquals(privateKey.getQ(), Utils.bigIntToBase64url(rsaPrivateKey.getPrimeQ()));
                Assert.assertEquals(privateKey.getDp(), Utils.bigIntToBase64url(rsaPrivateKey.getPrimeExponentP()));
                Assert.assertEquals(privateKey.getDq(), Utils.bigIntToBase64url(rsaPrivateKey.getPrimeExponentQ()));
                Assert.assertEquals(privateKey.getQi(), Utils.bigIntToBase64url(rsaPrivateKey.getCrtCoefficient()));

                RSAKey publicKey1 = RSAKey.builder()
                    .setN(Utils.bigIntToBase64url(rsaPublicKey.getModulus()))
                    .setE(Utils.bigIntToBase64url(rsaPublicKey.getPublicExponent()))
                    .build();

                RSAKey publicKey2 = RSAKey.keyBuilder(privateKey.getKey(false)).build();

                Map<String, Object> pubParts1 = privateKey.serialize(false);
                Map<String, Object> pubParts2 = publicKey1.serialize(false);
                Map<String, Object> pubParts3 = publicKey2.serialize(false);


                System.out.println(privateKey.serialize(true));
                System.out.println(pubParts1);
                System.out.println(pubParts2);
                System.out.println(pubParts3);


                Assert.assertNotNull(privateKey);
                Assert.assertNotNull(publicKey1);
                Assert.assertTrue(privateKey.getKey(true) instanceof  RSAPrivateCrtKey);
                Assert.assertEquals(rsaPrivateKey, (RSAPrivateCrtKey)privateKey.getKey(true));
                Assert.assertEquals(rsaPublicKey, (RSAPublicKey)privateKey.getKey(false));
                Assert.assertTrue(publicKey1.getKey(false) instanceof  RSAPublicKey);
                Assert.assertEquals(rsaPublicKey, (RSAPublicKey) publicKey1.getKey(false));
                Assert.assertTrue(publicKey1.equals(publicKey2));
                Assert.assertTrue(pubParts1.equals(pubParts2));
                Assert.assertTrue(pubParts2.equals(pubParts3));
            }
        }



    }

    @Test
    public void testSerializeRSAPrivateKeyWithN() throws IOException, JWKException ,
        SerializationNotPossible, NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = KeyUtils.getRSAPrivateKeyFromFile(PRIVATE_KEY_FILE);
        RSAKey rsaKey = RSAKey.loadKey(privateKey);
        Assert.assertFalse(Utils.isNullOrEmpty(rsaKey.getD()));
        Map<String, Object> serializedKey = rsaKey.serialize(true);

        System.out.println("serialized key = " + serializedKey.toString());
        System.out.printf("n = %s\n", (String)serializedKey.get(("n")));
        System.out.printf("e = %s\n", (String)serializedKey.get(("e")));
        System.out.printf("d = %s\n", (String)serializedKey.get(("d")));
        System.out.printf("p = %s\n", (String)serializedKey.get(("p")));
        System.out.printf("q = %s\n", (String)serializedKey.get(("q")));
        System.out.printf("dp = %s\n", (String)serializedKey.get(("dp")));
        System.out.printf("dq = %s\n", (String)serializedKey.get(("dq")));
        System.out.printf("qi = %s\n", (String)serializedKey.get(("qi")));

        RSAKey restoredKey = RSAKey.privateKeyBuilder(
            (String)serializedKey.get(("n")),
            (String)serializedKey.get(("e")),
            (String)serializedKey.get(("d")),
            (String)serializedKey.get(("p")),
            (String)serializedKey.get(("q")),
            (String)serializedKey.get(("dp")),
            (String)serializedKey.get(("dq")),
            (String)serializedKey.get(("qi")),
            (List<Map<String, String>>)serializedKey.get(("oth"))).build();

        Assert.assertEquals(rsaKey, restoredKey);

        BigInteger nModulus = Utils.base64urlToBigInt((String)serializedKey.get(("n")));
        BigInteger dExponent = Utils.base64urlToBigInt((String)serializedKey.get(("d")));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(nModulus, dExponent);
//        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(rsaPrivateKeySpec);
        PrivateKey rsaPrivateKey = keyFactory.generatePrivate(rsaPrivateKeySpec);
        if(rsaPrivateKey instanceof  RSAPrivateCrtKey) {
            System.out.println("Hello");
        }




    }

}
