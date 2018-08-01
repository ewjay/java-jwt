package com.auth0.msg;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
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
    private static final String INVALID_PUBLIC_KEY_FILE =
        "src/test/resources/rsa-public_invalid.pem";
    private static final String JSON_PUBLIC_KEY_FILE = "src/test/resources/jwk.json";
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

    private static final String JWK2STRING = "{\"keys\": " +
        "[{\"x5t\": \"kriMPdmBvx68skT8-mPAB3BseeA\", " +
        "\"use\": \"sig\", " +
        "\"n\": \"kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS_AHsBeQPqYygfYVJL" +
        "6_EgzVuwRk5txr9e3n1uml94fLyq_AXbwo9yAduf4dCHTP8CWR1dnDR-Qnz_4PYlWVEuuHHONOw_blbfdMjhY-C_" +
        "BYM2E3pRxbohBb3x__CfueV7ddz2LYiH3wjz0QS_7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd_GTgWN8A" +
        "-6SN1r4hzpjFKFLbZnBt77ACSiYx-IHK4Mp-NaVEi5wQtSsjQtI--XsokxRDqYLwus1I1SihgbV_STTg5enufuw" +
        "\", \"e\": \"AQAB\", " +
        "\"kty\": \"RSA\", " +
        "\"x5c\": [\"MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFj" +
        "Y291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAt" +
        "MSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOC" +
        "AQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqY" +
        "ygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfd" +
        "MjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/" +
        "GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5" +
        "enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMu" +
        "YWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF7" +
        "7EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajy" +
        "vlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YL" +
        "nsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg7" +
        "0dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ\"], \"kid\": \"kriM" +
        "PdmBvx68skT8-mPAB3BseeA\", " +
        "\"issuer\": \"https://login.microsoftonline.com/{tenantid}/v2.0/\"}, " +
        "{\"x5t\": \"MnC_VZcATfM5pOYiJHMba9goEKY\", " +
        "\"use\": \"sig\", " +
        "\"n\": \"vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq-RtwN1Vs_" +
        "z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW_EW_P-C8bb2dCGXhBYqPfHyimvz2" +
        "WarXhntPSbM5XyS5v5yCw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2K" +
        "q6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3-T-IAbsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ" +
        "\", " +
        "\"e\": \"AQAB\", " +
        "\"kty\": \"RSA\", " +
        "\"x5c\": [\"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQD" +
        "EyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAw" +
        "MFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEB" +
        "BQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1f" +
        "U5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4" +
        "QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnh" +
        "SDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TT" +
        "oX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJex" +
        "qPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCy" +
        "pxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w" +
        "8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R" +
        "8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\"], " +
        "\"kid\": \"MnC_VZcATfM5pOYiJHMba9goEKY\", " +
        "\"issuer\": \"https://login.microsoftonline.com/{tenantid}/v2.0/\"}, " +
        "{\"x5t\": \"GvnPApfWMdLRi8PDmisFn7bprKg\", " +
        "\"use\": \"sig\", " +
        "\"n\": \"5ymq_xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMRG7sJq-UWOKVOA4MVrd_NdV-e" +
        "jj1DE5MPSiG-mZK_5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ48thXOTED0o" +
        "Na6U\", " +
        "\"e\": \"AQAB\", " +
        "\"kty\": \"RSA\", " +
        "\"x5c\": [\"MIICWzCCAcSgAwIBAgIJAKVzMH2FfC12MA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUg" +
        "SUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xMzExMTExODMzMDhaFw0xNjExMTAxODMzMDhaMCkxJzAlBgNV" +
        "BAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA5ymq" +
        "/xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMRG7sJq+UWOKVOA4MVrd/NdV+ejj1DE5MPSiG+m" +
        "ZK/5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ48thXOTED0oNa6UCAwEAAaOB" +
        "ijCBhzAdBgNVHQ4EFgQURCN+4cb0pvkykJCUmpjyfUfnRMowWQYDVR0jBFIwUIAURCN+4cb0pvkykJCUmpjyfUfn" +
        "RMqhLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAKVzMH2FfC12MAsGA1Ud" +
        "DwQEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQB8v8G5/vUl8k7xVuTmMTDA878AcBKBrJ/Hp6RShmdqEGVI7SFR7IlB" +
        "N1//NwD0n+IqzmnRV2PPZ7iRgMF/Fyvqi96Gd8X53ds/FaiQpZjUUtcO3fk0hDRQPtCYMII5jq+YAYjSybvF84sa" +
        "B7HGtucVRn2nMZc5cAC42QNYIlPMqA==\"], " +
        "\"kid\": \"GvnPApfWMdLRi8PDmisFn7bprKg\", " +
        "\"issuer\": " +
        "\"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/\"}, " +
        "{\"x5t\": \"dEtpjbEvbhfgwUI-bdK5xAU_9UQ\", " +
        "\"use\": \"sig\", " +
        "\"n\": \"x7HNcD9ZxTFRaAgZ7-gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQeSML7qZPlowb5BUakdLI70a" +
        "yM4vN36--0ht8-oCHhl8YjGFQkU-Iv2yahWHEP-1EK6eOEYu6INQP9Lk0HMk3QViLwshwb-KXVD02jdmX2HNdYJ" +
        "dPyc0c\", \"e\": \"AQAB\", \"kty\": \"RSA\", \"x5c\": [\"MIICWzCCAcSgAwIBAgIJAL3MzqqEFM" +
        "YjMA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xM" +
        "zExMTExOTA1MDJaFw0xOTExMTAxOTA1MDJaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGlj" +
        "IEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx7HNcD9ZxTFRaAgZ7+gdYLkgQua3zvQseqBJIt8Uq3M" +
        "imInMZoE9QGQeSML7qZPlowb5BUakdLI70ayM4vN36++0ht8+oCHhl8YjGFQkU+Iv2yahWHEP+1EK6eOEYu6INQ" +
        "P9Lk0HMk3QViLwshwb+KXVD02jdmX2HNdYJdPyc0cCAwEAAaOBijCBhzAdBgNVHQ4EFgQULR0aj9AtiNMgqIY8Z" +
        "yXZGsHcJ5gwWQYDVR0jBFIwUIAULR0aj9AtiNMgqIY8ZyXZGsHcJ5ihLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQg" +
        "U1RTIFNpZ25pbmcgUHVibGljIEtleYIJAL3MzqqEFMYjMAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQB" +
        "shrsF9yls4ArxOKqXdQPDgHrbynZL8m1iinLI4TeSfmTCDevXVBJrQ6SgDkihl3aCj74IEte2MWN78sHvLLTWTA" +
        "kiQSlGf1Zb0durw+OvlunQ2AKbK79Qv0Q+wwGuK+oymWc3GSdP1wZqk9dhrQxb3FtdU2tMke01QTut6wr7ig==\"" +
        "], " +
        "\"kid\": \"dEtpjbEvbhfgwUI-bdK5xAU_9UQ\", " +
        "\"issuer\": " +
        "\"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/\"}]}";

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
        KeyBundle keyBundle3 = KeyBundle.keyBundleFromLocalFile(
            PRIVATE_KEY_FILE, "der", usage);

        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle1);
        keyJar.addKeyBundle("http://www.example.org", keyBundle2);
        keyJar.addKeyBundle("http://www.example.org", keyBundle3);

        List<Key> ownerKeys = keyJar.getKeys(
            "sig", "RSA", "http://www.example.org/", "", null);
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
        KeyBundle keyBundle3 =
            KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle1);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle2);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle3);

        List<Key> ownerKeys = keyJar.getKeys(
            "sig", "RSA", "http://www.example.org", "", null);
        Assert.assertNotNull(ownerKeys);
        Assert.assertEquals(ownerKeys.size(), 1);
    }

    @Test
    public void testMissingSlash2() throws Exception {
        JSONParser jsonParser = new JSONParser();
        String json = "[{" +
            "\"kty\": \"oct\"," +
            "\"k\": \"a1b2c3d4\"," +
            "\"use\": \"sig\"" +
            "}," +
            "{" +
            "\"kty\": \"oct\"," +
            "\"k\": \"a1b2c3d4\"," +
            "\"use\": \"ver\"" +
            "}" +
            "]";
        Object jsonObject = jsonParser.parse(json);
        List<Map<String, Object>> list = (List<Map<String, Object>>) jsonObject;
        KeyBundle keyBundle1 = new KeyBundle(list);


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
        KeyBundle keyBundle =
            KeyBundle.keyBundleFromLocalFile(JSON_PUBLIC_KEY_FILE, "jwks", usage);
        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle);

        Map<String, List<Map<String, Object>>> keysJwks =
            keyJar.exportsJwks(false, "");
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

    @Ignore
    public void testNoUse() throws Exception {

    }


    @Test
    public void testProvider() throws Exception {
        Map<String, Object> pcr = new HashMap<String, Object>();
        pcr.put("jwks_uri", "https://connect-op.herokuapp.com/jwks.json");
        KeyJar keyJar = new KeyJar();
        keyJar.loadKeys(pcr, "https://connect-op.heroku.com", false);
        List<Key> keys = keyJar.getIssuerKeys("https://connect-op.heroku.com");
        Assert.assertEquals(keys.size(), 1);
    }



    @Test
    public void testImportJwks() throws Exception {
        JSONParser jsonParser = new JSONParser();
        Object json = jsonParser.parse(JWK1STRING);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");
        List<Key> keys = keyJar.getIssuerKeys("");
        Assert.assertEquals(keys.size(), 4);

    }

    @Test
    public void testGetSigningKeyUseUndefined() throws Exception {
        JSONParser jsonParser = new JSONParser();
        Object json = jsonParser.parse(JWK1STRING);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");
        List<Key> key1 = keyJar.getSigningKey("", "", "rsa1", null);
        Assert.assertEquals(key1.size(), 1);
        List<Key> key2 = keyJar.getSigningKey("RSA", "", "", null);
        Assert.assertEquals(key2.size(), 1);
        List<Key> key3 = keyJar.getSigningKey("RSA", "", "rsa1", null);
        Assert.assertEquals(key3.size(), 1);
    }


    @Test
    public void testJWK2() throws Exception {
        JSONParser jsonParser = new JSONParser();
        Object json = jsonParser.parse(JWK2STRING);
        System.out.println(json);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");

    }
}