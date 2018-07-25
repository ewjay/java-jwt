package com.auth0.msg;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class KeyJarTest {

    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE = "src/test/resources/rsa-public_invalid.pem";
    private static final String JSON_PUBLIC_KEY_FILE = "src/test/resources/jwk.json";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testKeyJarAdd() throws Exception {
        KeyJar keyJar = new KeyJar();
        ArrayList<String> uses = new ArrayList<String>();
        uses.add("ver");
        uses.add("sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", uses);
        keyJar.addKeyBundle("https://issuer.example.com", keyBundle);
        List<String> owners = keyJar.getOwners();
        Assert.assertEquals(owners.get(0), "https://issuer.example.com");
    }

    @Test
    public void testSetBundle() throws Exception {
        KeyJar keyJar = new KeyJar();
        ArrayList<String> uses = new ArrayList<String>();
        uses.add("ver");
        uses.add("sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", uses);
        ArrayList<KeyBundle> kbList = new ArrayList<KeyBundle>();
        kbList.add(keyBundle);
        keyJar.setBundle("https://issuer.example.com", kbList);
        List<String> owners = keyJar.getOwners();
        Assert.assertEquals(owners.get(0), "https://issuer.example.com");
    }


    @Test
    public void testAddSymmetric() throws Exception {
        KeyJar keyJar = new KeyJar();
        ArrayList<String> uses = new ArrayList<String>();
        uses.add("sig");
        keyJar.addSymmetricKey("", "client_secret".getBytes(), uses);
        List<String> owners = keyJar.getOwners();
        List<Key> symKeys = keyJar.getSigningKey("oct", "", "", null);
        Assert.assertEquals(owners.get(0), "");
        Assert.assertEquals(symKeys.size(), 1);
    }


    @Test
    public void testExtraSlash() throws Exception {
        Map<String, Object> k1 = new HashMap<>();
        k1.put("kty", "oct");
        k1.put("k", "a1b2c3d4");
        k1.put("use", "sig");
        Map<String, Object> k2 = new HashMap<>();
        k2.put("kty", "oct");
        k2.put("k", "a1b2c3d4");
        k2.put("use", "ver");
        List<Map<String, Object>> keyList1 = new ArrayList<>();
        keyList1.add(k1);
        keyList1.add(k2);
        KeyBundle keyBundle1 = new KeyBundle(keyList1);

        Map<String, Object> k3 = new HashMap<>();
        k3.put("kty", "oct");
        k3.put("k", "e5f6g7h8");
        k3.put("use", "sig");
        Map<String, Object> k4 = new HashMap<>();
        k4.put("kty", "oct");
        k4.put("k", "e5f6g7h8");
        k4.put("use", "ver");
        List<Map<String, Object>> keyList2 = new ArrayList<>();
        keyList2.add(k3);
        keyList2.add(k4);
        KeyBundle keyBundle2 = new KeyBundle(keyList2);
        List<String> usage = new ArrayList<>();
        usage.add("ver");
        usage.add("sig");
        KeyBundle keyBundle3 = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle1);
        keyJar.addKeyBundle("http://www.example.org", keyBundle2);
        keyJar.addKeyBundle("http://www.example.org", keyBundle3);

        List<Key> ownerKeys = keyJar.getKeys("sig", "RSA", "http://www.example.org/", "", null);
        Assert.assertNotNull(ownerKeys);
        Assert.assertEquals(ownerKeys.size(), 1);
    }

    @Test
    public void testIssuerMissingSlash() throws Exception {
        Map<String, Object> k1 = new HashMap<>();
        k1.put("kty", "oct");
        k1.put("k", "a1b2c3d4");
        k1.put("use", "sig");
        Map<String, Object> k2 = new HashMap<>();
        k2.put("kty", "oct");
        k2.put("k", "a1b2c3d4");
        k2.put("use", "ver");
        List<Map<String, Object>> keyList1 = new ArrayList<>();
        keyList1.add(k1);
        keyList1.add(k2);
        KeyBundle keyBundle1 = new KeyBundle(keyList1);

        Map<String, Object> k3 = new HashMap<>();
        k3.put("kty", "oct");
        k3.put("k", "e5f6g7h8");
        k3.put("use", "sig");
        Map<String, Object> k4 = new HashMap<>();
        k4.put("kty", "oct");
        k4.put("k", "e5f6g7h8");
        k4.put("use", "ver");
        List<Map<String, Object>> keyList2 = new ArrayList<>();
        keyList2.add(k3);
        keyList2.add(k4);
        KeyBundle keyBundle2 = new KeyBundle(keyList2);
        List<String> usage = new ArrayList<>();
        usage.add("ver");
        usage.add("sig");
        KeyBundle keyBundle3 = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle1);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle2);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle3);

        List<Key> ownerKeys = keyJar.getKeys("sig", "RSA", "http://www.example.org", "", null);
        Assert.assertNotNull(ownerKeys);
        Assert.assertEquals(ownerKeys.size(), 1);
    }

    @Ignore
    public void testGetEnc() throws Exception {

    }


    @Ignore
    public void testEncNotMine() throws Exception {
    }


    @Test
    public void testDumpIssuerKeys() throws Exception {
        List<String> usage = new ArrayList<>();
        usage.add("sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(JSON_PUBLIC_KEY_FILE, "jwks", usage);
        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle);

        Map<String, List<Map<String, Object>>> keysJwks = keyJar.exportsJwks(false, "");
        Assert.assertNotNull(keysJwks);
        List<Map<String, Object>> keys = keysJwks.get("keys");
        Assert.assertEquals(keys.size(), 1);
        Map<String, Object> keyInfo = keys.get(0);
        Assert.assertEquals(keyInfo.get("use"), "sig");
        Assert.assertEquals(keyInfo.get("e"), "AQAB");
        Assert.assertEquals(keyInfo.get("n"), "pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n" +
            "-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE" +
            "-Yopfu3B58Q" +
            "lgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf" +
            "-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JB" +
            "qaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ" +
            "-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9Rfz" +
            "T87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw");
        Assert.assertEquals(keyInfo.get("kty"), "RSA");
        Assert.assertEquals(keyInfo.get("kid"), "abc");
        Assert.assertEquals(keyInfo.get("alg"), "RS256");
    }


}