package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


public class KeyBundleTest {
    private static JSONParser jsonParser = new JSONParser();
    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String JSON_PUBLIC_KEY_FILE = "src/test/resources/jwk.json";


    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }


    @Test
    public void testCreatStoreRSAKeyPair() throws Exception {
        Path currentRelativePath = Paths.get("");
        String s = currentRelativePath.toAbsolutePath().toString();
        System.out.println("Current relative path is: " + s);

        String filename = "testkey";
        String privateFilename = s + File.separator + filename;
        String publicFilename = s + File.separator + filename + ".pub";


        KeyBundle.createStoreRSAKeyPair(filename, s, 2048, null);

        File privateFile = new File(privateFilename);
        File publicFile = new File(publicFilename);
        Assert.assertTrue(publicFile.exists());
        Assert.assertTrue(privateFile.exists());
        PublicKey publicKey = KeyUtils.readRSAPublicKeyFromFile(publicFilename);
        PrivateKey privateKey = KeyUtils.readRSAPrivateKeyFromFile(privateFilename);
        Assert.assertNotNull(publicKey);
        Assert.assertTrue(publicKey instanceof PublicKey);

        Assert.assertNotNull(privateKey);
        Assert.assertTrue(privateKey instanceof PrivateKey);
        privateFile.delete();
        publicFile.delete();
    }


    @Test
    public void testSymKey() throws ParseException, ImportException, IOException, JWKException, ValueError {
        String k = Base64.encodeBase64URLSafeString("supersecret".getBytes(Charset.forName("UTF-8")));
        String json = "[{\"kty\": \"oct\", \"k\": \"" +
            k +
            "\", \"use\": \"sig\"}]";

        List<Map<String, Object>> jsonObject  = (List<Map<String, Object>>)jsonParser.parse(json);

        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(1, keyBundle.get("oct").size());
        Assert.assertEquals(0, keyBundle.get("rsa").size());
    }

    @Test
    public void testWith2SymKey() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));

        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));

        String json = "[{\"kty\": \"oct\", \"k\": \"" + secretA +  "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"enc\"}]";

        List<Map<String, Object>> jsonObject  = (List<Map<String, Object>>)jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(2, keyBundle.get("oct").size());
        Assert.assertEquals(2, keyBundle.getKeys().size());
        Assert.assertNull(keyBundle.getKeyWithKid("kid"));
        Assert.assertEquals(0, keyBundle.getKids().size());
    }

    @Test
    public void testRemoveSym() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));

        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));

        String json = "[{\"kty\": \"oct\", \"k\": \"" + secretA + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"enc\"}]";

        List<Map<String, Object>> jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(2, keyBundle.getKeys().size());
        List<Key> keys = keyBundle.get("oct");
        keyBundle.remove(keys.get(0));
        Assert.assertEquals(1, keyBundle.getKeys().size());
    }

    @Test
    public void testRemoveKeySym() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));

        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));

        String json = "[{\"kty\": \"oct\", \"k\": \"" + secretA + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"enc\"}]";

        List<Map<String, Object>> jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(2, keyBundle.getKeys().size());
        List<Key> keys = keyBundle.get("oct");
        keyBundle.remove(keys.get(0));
        Assert.assertEquals(1, keyBundle.getKeys().size());
        keyBundle.removeKeysByType("rsa");
        Assert.assertEquals(1, keyBundle.getKeys().size());

    }


    @Test
    public void testRSAInit() throws ParseException, ImportException {
        String json = "{\"use\": [\"enc\", \"sig\"], \"size\": 1024, " +
            "\"name\": \"rsa\", \"path\": \"keys\"}";

        Map<String, Object> jsonObject = (Map<String, Object>) jsonParser.parse(json);
        KeyBundle keyBundle = KeyBundle.rsaInit(jsonObject);
        Assert.assertNotNull(keyBundle);
        Assert.assertEquals(2, keyBundle.getKeys().size());
        Assert.assertEquals(2, keyBundle.get("rsa").size());
    }

    @Test
    public void testRSAInitUnderSpec() throws ParseException, ImportException {
        String json = "{\"use\": [\"enc\", \"sig\"], \"size\": 1024}";

        Map<String, Object> jsonObject = (Map<String, Object>) jsonParser.parse(json);
        KeyBundle keyBundle = KeyBundle.rsaInit(jsonObject);
        Assert.assertNotNull(keyBundle);
        Assert.assertEquals(2, keyBundle.getKeys().size());
        Assert.assertEquals(2, keyBundle.get("rsa").size());
    }

    @Test
    public void testUnknownSource() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        exception.expect(ImportException.class);
        KeyBundle keyBundle = new KeyBundle("foobar", true);
    }

    @Test
    public void testUnknownTypes() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String json = "[{\"kid\":\"q-H9y8iuh3BIKZBbK6S0mH_isBlJsk-u6VtZ5rAdBo5fCjjy3LnkrsoK_QWr" +
            "lKB08j_PcvwpAMfTEDHw5spepw\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"kty\":\"OKP\"," +
            "\"crv\":\"Ed25519\",\"x\":\"FnbcUAXZ4ySvrmdXK1MrDuiqlqTXvGdAaE4RWZjmFIQ\"}]";

        List<Map<String, Object>> jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(0, keyBundle.getKeys().size());
    }

    @Test
    public void testRemoveRSA() throws ParseException {
        String json = "{\"use\": [\"enc\", \"sig\"], \"size\": 1024, " +
            "\"name\": \"rsa\", \"path\": \"keys\"}";

        Map<String, Object> jsonObject = (Map<String, Object>) jsonParser.parse(json);
        KeyBundle keyBundle = KeyBundle.rsaInit(jsonObject);
        Assert.assertNotNull(keyBundle);
        Assert.assertEquals(2, keyBundle.getKeys().size());
        List<Key> keys = keyBundle.get("rsa");
        Assert.assertEquals(2, keys.size());
        keyBundle.remove(keys.get(0));
        Assert.assertEquals(1, keyBundle.getKeys().size());
    }

    @Test
    public void testKeyMix()throws ParseException, ImportException, ValueError,
        DeserializationNotPossible {
        String json = "{\"use\": [\"enc\", \"sig\"], \"size\": 1024, \"name\": \"rsa\", " +
            "\"path\": \"keys\"}";

        Map<String, Object> jsonObject = (Map<String, Object>) jsonParser.parse(json);
        KeyBundle keyBundle = KeyBundle.rsaInit(jsonObject);
        SYMKey symKey = new SYMKey("enc", Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8"))));

        keyBundle.append(symKey);
        Assert.assertEquals(3, keyBundle.getKeys().size());
        Assert.assertEquals(2, keyBundle.get("rsa").size());
        Assert.assertEquals(1, keyBundle.get("oct").size());
        keyBundle.remove(symKey);
        Assert.assertEquals(2, keyBundle.getKeys().size());
        Assert.assertEquals(2, keyBundle.get("rsa").size());
        Assert.assertEquals(0, keyBundle.get("oct").size());
    }

    @Test
    public void testGetAllKeys()throws ParseException, ImportException, ValueError,
        DeserializationNotPossible {
        String json = "{\"use\": [\"enc\", \"sig\"], \"size\": 1024, \"name\": \"rsa\", " +
            "\"path\": \"keys\"}";

        Map<String, Object> jsonObject = (Map<String, Object>) jsonParser.parse(json);
        KeyBundle keyBundle = KeyBundle.rsaInit(jsonObject);
        SYMKey symKey = new SYMKey("enc", Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8"))));

        keyBundle.append(symKey);
        Assert.assertEquals(3, keyBundle.get(null).size());
        Assert.assertEquals(3, keyBundle.getKeys().size());
   }


    @Test
    public void testKeyBundleFromLocalDer()throws ImportException, UnknownKeyType, IOException, JWKException, ValueError  {
        List<String> usage = new ArrayList<>();
        usage.add("enc");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        Assert.assertEquals(1, keyBundle.getLength());
        List<Key> keys = keyBundle.get("rsa");
        Assert.assertEquals(1, keys.size());
        Assert.assertTrue(keys.get(0) instanceof  RSAKey );
    }



    @Test
    public void testKeyBundleFromLocalDerUpdate()throws ImportException, IOException, JWKException, ValueError ,
        UnknownKeyType {
        List<String> usage = new ArrayList<>();
        usage.add("enc");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        Assert.assertEquals(1, keyBundle.getLength());
        List<Key> keys = keyBundle.get("rsa");
        Assert.assertEquals(1, keys.size());
        Assert.assertTrue(keys.get(0) instanceof  RSAKey );

        keyBundle.update();
        keys = keyBundle.get("rsa");
        Assert.assertEquals(1, keys.size());
        Assert.assertTrue(keys.get(0) instanceof  RSAKey );
    }


    @Test
    public void testCreateJwksSym()
        throws ParseException, ImportException, SerializationNotPossible, IOException, JWKException, ValueError  {
        String k = Base64.encodeBase64URLSafeString("supersecret".getBytes(Charset.forName("UTF-8")));
        String json = "[{\"kty\": \"oct\", \"k\": \"" +
            k +
            "\", \"use\": \"sig\"}]";

        List<Map<String, Object>> jsonObject  = (List<Map<String, Object>>)jsonParser.parse(json);

        KeyBundle keyBundle = new KeyBundle(jsonObject);
        String jwks = keyBundle.jwks();
        Object loc = jsonParser.parse(jwks);
        Set<String> keySet = new HashSet<>();
        keySet.add("keys");
        Assert.assertEquals(((Map<String, Object>) loc).keySet(), keySet);
        keySet.remove("keys");
        keySet.add("kty");
        keySet.add("use");
        keySet.add("k");
        Assert.assertEquals(((Map<String, Object>)((List<Object>)((Map<String, Object>) loc).get("keys")).get(0)).keySet(), keySet);
    }

    @Test
    public void testKeyBundleFromLocalJwksFile() throws ParseException, ImportException, UnknownKeyType, IOException, JWKException, ValueError  {
        List<String> usage = new ArrayList<>();
        usage.add("sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile("file://" + JSON_PUBLIC_KEY_FILE, "jwks", usage);
        Assert.assertEquals(1, keyBundle.getLength());
    }


    @Test
    public void testKeyBundleFromLocalJwks() throws ParseException, ImportException, UnknownKeyType, IOException, JWKException, ValueError  {
        List<String> usage = new ArrayList<>();
        usage.add("sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(JSON_PUBLIC_KEY_FILE, "jwks", usage);
        Assert.assertEquals(1, keyBundle.getLength());
    }

    @Test
    public void testUpdate() throws ParseException, ImportException , IOException, JWKException, ValueError {
        String k = Base64.encodeBase64URLSafeString("supersecret".getBytes(Charset.forName("UTF-8")));
        String json = "[{\"kty\": \"oct\", \"k\": \"" +
            k +
            "\", \"use\": \"sig\"}]";

        List<Map<String, Object>> jsonObject  = (List<Map<String, Object>>)jsonParser.parse(json);

        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(1, keyBundle.get("oct").size());
        Assert.assertEquals(0, keyBundle.get("rsa").size());

        keyBundle.update();
        Assert.assertEquals(1, keyBundle.get("oct").size());
        Assert.assertEquals(0, keyBundle.get("rsa").size());
    }

    @Test
    public void testUpdateRSA() throws ParseException, ImportException, UnknownKeyType, IOException, JWKException, ValueError  {
        List<String> usage = new ArrayList<>();
        usage.add("sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);
        Assert.assertEquals(0, keyBundle.get("oct").size());
        Assert.assertEquals(1, keyBundle.get("rsa").size());
        Key key = keyBundle.get("RSA").get(0);
        Assert.assertTrue(key instanceof  RSAKey);
        keyBundle.update();
        Assert.assertEquals(0, keyBundle.get("oct").size());
        Assert.assertEquals(1, keyBundle.get("rsa").size());
        key = keyBundle.get("RSA").get(0);
        Assert.assertTrue(key instanceof  RSAKey);
    }

    @Test
    public void testOutdated() throws ParseException, ImportException, IOException, JWKException, ValueError {
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));

        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));

        String json = "[{\"kty\": \"oct\", \"k\": \"" + secretA + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"enc\"}]";

        List<Map<String, Object>> jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);
        Assert.assertEquals(2, keyBundle.getLength());
        List<Key> keys = keyBundle.getKeys();
        long now = System.currentTimeMillis();
        keys.get(0).setInactiveSince(now - 60000);
        keyBundle.removeOutdated(30000, 0);

        Assert.assertEquals(1, keyBundle.getLength());
    }

    @Test
    public void testDumpJwks() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String json1 = "{\"use\": [\"enc\", \"sig\"], \"size\": 1024, " +
            "\"name\": \"rsa\", \"path\": \"keys\"}";
        Map<String, Object> jsonObject = (Map<String, Object>) jsonParser.parse(json1);
        KeyBundle keyBundle1 = KeyBundle.rsaInit(jsonObject);
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));
        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));
        String json2 = "[{\"kty\": \"oct\", \"k\": \"" + secretA + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"enc\"}]";

        List<Map<String, Object>> jsonObject2 = (List<Map<String, Object>>) jsonParser.parse(json2);
        KeyBundle keyBundle2 = new KeyBundle(jsonObject2);
        List<KeyBundle> keyBundleList = new ArrayList<>();
        keyBundleList.add(keyBundle1);
        keyBundleList.add(keyBundle2);
        keyBundle1.dumpJwks(keyBundleList, "", false);


    }

    @Test
    public void testMarkAsInactive() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));

        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));

        String json = "[{\"kty\": \"oct\", \"k\": \"" + secretA + "\", \"use\": \"sig\"}]";

        List<Map<String, Object>> jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);

        Assert.assertEquals(1, keyBundle.getLength());
        List<Key> keys = keyBundle.getKeys();
        for(Key key : keys) {
            keyBundle.markAsInactive(key.getKid());
        }
        json = "[{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"sig\"}]";
        jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        keyBundle.doKeys(jsonObject);

        Assert.assertEquals(2, keyBundle.getLength());
        Assert.assertEquals(1, keyBundle.getActiveKeys().size());
    }


    @Test
    public void testCopy() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String secretA = Base64.encodeBase64URLSafeString(
            "supersecret".getBytes(Charset.forName("UTF-8")));

        String secretB = Base64.encodeBase64URLSafeString(
            "secret".getBytes(Charset.forName("UTF-8")));

        String json = "[{\"kty\": \"oct\", \"k\": \"" + secretA + "\", \"use\": \"sig\"}]";

        List<Map<String, Object>> jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        KeyBundle keyBundle = new KeyBundle(jsonObject);

        Assert.assertEquals(1, keyBundle.getLength());
        List<Key> keys = keyBundle.getKeys();
        for(Key key : keys) {
            keyBundle.markAsInactive(key.getKid());
        }
        json = "[{\"kty\": \"oct\", \"k\": \"" + secretB + "\", \"use\": \"sig\"}]";
        jsonObject = (List<Map<String, Object>>) jsonParser.parse(json);
        keyBundle.doKeys(jsonObject);

        KeyBundle kb = keyBundle.copy();

        Assert.assertEquals(2, kb.getLength());
        Assert.assertEquals(1, kb.getActiveKeys().size());
    }
}
