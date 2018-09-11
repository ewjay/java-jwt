package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

public class ECKeyTest {
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
    public void testGenECKey() {
        String curves[] = new String[]{"P-256", "P-384", "P-521"};
        for(String curve : curves) {
            KeyPair keyPair = ECKey.generateECKeyPair(curve);
            Assert.assertNotNull(keyPair);
            Assert.assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
            Assert.assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        }
    }


    @Test
    public void testImportECKey() throws Exception, SerializationNotPossible {
        JSONObject ecObject = (JSONObject) jsonParser.parse(ECKEY);
        ECKey ecKey = new ECKey("", "", "", null,
            (String)ecObject.get("crv"), (String)ecObject.get("x"), (String)ecObject.get("y"),
            (String)ecObject.get("d"), null);
        ecKey.deserialize();
        Assert.assertTrue(ecKey.key instanceof ECPrivateKey);
    }

    @Test
    public void testCompareNegEC() throws ValueError, SerializationNotPossible, HeaderError,
        JWKException, ParseException {
        KeyPair keyPair = ECKey.generateECKeyPair("P-256");

        ECKey ecKey1 = new ECKey("", "", "", (java.security.Key) keyPair.getPrivate(),
            "P-256", "", "", "", null);
        Map<String, Object> ecObject = (Map<String, Object>)jsonParser.parse(ECKEY);
        ECKey ecKey2 = new ECKey("", "", "", null,
            (String)ecObject.get("crv"), (String)ecObject.get("x"), (String)ecObject.get("y"),
            (String)ecObject.get("d"), null);
        Assert.assertNotEquals(ecKey1, ecKey2);
    }

    @Test
    public void testGetnerateUnsupportedCurve() throws Exception {
        KeyPair keyPair = ECKey.generateECKeyPair("P-236");
        Assert.assertNull(keyPair);
    }


    @Test
    public void testGetPrivateKeyFromPublicKey() throws Exception, SerializationNotPossible {
        KeyPair keyPair = ECKey.generateECKeyPair("P-256");
        Assert.assertNotNull(keyPair);
        ECKey privateEC = new ECKey("", "", "", (Key) keyPair.getPrivate(),
            "P-256", "", "", "", null);
        ECKey publicEC = new ECKey("", "", "", (Key) keyPair.getPublic(),
            "P-256", "", "", "", null);
        exception.expect(ValueError.class);
        publicEC.getKey(true);

    }


    @Test
    public void testGetKey() throws Exception, SerializationNotPossible {
        KeyPair keyPair = ECKey.generateECKeyPair("P-256");
        Assert.assertNotNull(keyPair);
        ECKey privateEC = new ECKey("", "", "", (Key) keyPair.getPrivate(),
            "P-256", "", "", "", null);
        ECKey publicEC = new ECKey("", "", "", (Key) keyPair.getPublic(),
            "P-256", "", "", "", null);
        SYMKey symKey = new SYMKey("",
            Base64.encodeBase64URLSafeString("mekmitasdigoat".getBytes("UTF-8")));
        Assert.assertTrue(publicEC.getKey(false) instanceof ECPublicKey);
        Assert.assertTrue(privateEC.getKey(true) instanceof ECPrivateKey);

    }

}
