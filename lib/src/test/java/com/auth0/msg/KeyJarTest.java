package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
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

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class KeyJarTest {

    private static JSONParser jsonParser = new JSONParser();
    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
    private static final String INVALID_PUBLIC_KEY_FILE =
        "src/test/resources/rsa-public_invalid.pem";
    private static final String JSON_PUBLIC_KEY_FILE = "src/test/resources/jwk.json";
    private static final String JWK0STRING = "{\"keys\": [" +
        "{\"kty\": \"RSA\", \"e\": \"AQAB\", \"kid\": \"abc\"," +
        "\"n\":\"wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5Da" +
        "egvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6J" +
        "tu82nB5k8\"}]}";
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

    private static final String JWKS_SPO = "{\"keys\":[" +
        "{\"use\":\"sig\",\"crv\":\"P-256\",\"kty\":\"EC\",\"alg\":\"ES256\"," +
        "\"y\":\"ac1h_DwyuUxhkrD9oKMJ-b_KuiVvvSARIwT-XoEmDXs\"," +
        "\"x\":\"1XXUXq75gOPZ4bEj1o2Z5XKJWSs6LmL6fAOK3vyMzSc\"," +
        "\"kid\":\"BfxfnahEtkRBG3Hojc9XGLGht_5rDBj49Wh3sBDVnzRpulMqYwMRmpizA0aSPT1fhCHYivTiaucWU" +
        "qFu_GwTqA\"}," +
        "{\"use\":\"sig\",\"crv\":\"P-256\",\"kty\":\"EC\",\"alg\":\"ES256\"," +
        "\"y\":\"ycvkFMBIzgsowiaf6500YlG4vaMSK4OF7WVtQpUbEE0\"," +
        "\"x\":\"2DfQoLpZS2j3hHEcHDkzV8ISx-RdLt6Opy8YZYVm4AQ\"," +
        "\"kid\":\"91pD1H81rXUvrfg9mkngIG-tXjnldykKUVbITDIU1SgJvq91b8clOcJuEHNAq61eIvg8owpEvWcW" +
        "AtlbV2awyA\"}," +
        "{\"use\":\"sig\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"alg\":\"RS256\"," +
        "\"n\":\"yG9914Q1j63Os4jX5dBQbUfImGq4zsXJD4R59XNjGJlEt5ek6NoiDl0ucJO3_7_R9e5my2ONTSqZhtzF" +
        "W6MImnIn8idWYzJzO2EhUPCHTvw_2oOGjeYTE2VltIyY_ogIxGwY66G0fVPRRH9tCxnkGOrIvmVgkhCCGkamqeXu" +
        "Wvx9MCHL_gJbZJVwogPSRN_SjA1gDlvsyCdA6__CkgAFcSt1sGgiZ_4cQheKexxf1-7l8R91ZYetz53drk2FS3Sf" +
        "uMZuwMM4KbXt6CifNhzh1Ye-5Tr_ZENXdAvuBRDzfy168xnk9m0JBtvul9GoVIqvCVECB4MPUb7zU6FTIcwRAw\"" +
        ",\"kid\":\"0sIEl3MUJiCxrqleEBBF-_bZq5uClE84xp-wpt8oOI-WIeNxBjSR4ak_OTOmLdndB0EfDLtC7X1Jr" +
        "nfZILJkxA\"}," +
        "{\"use\":\"sig\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"alg\":\"RS256\"," +
        "\"n\":\"68be-nJp46VLj4Ci1V36IrVGYqkuBfYNyjQTZD_7yRYcERZebowOnwr3w0DoIQpl8iL2X8OXUo7rUW_" +
        "LMzLxKx2hEmdJfUn4LL2QqA3KPgjYz8hZJQPG92O14w9IZ-8bdDUgXrg9216H09yq6ZvJrn5Nwvap3MXgECEzsZ" +
        "6zQLRKdb_R96KFFgCiI3bEiZKvZJRA7hM2ePyTm15D9En_Wzzfn_JLMYgE_DlVpoKR1MsTinfACOlwwdO9U5Dm-" +
        "5elapovILTyVTgjN75i-wsPU2TqzdHFKA-4hJNiWGrYPiihlAFbA2eUSXuEYFkX43ahoQNpeaf0mc17Jt5kp7pM" +
        "2w\"," +
        "\"kid\":\"zyDfdEU7pvH0xEROK156ik8G7vLO1MIL9TKyL631kSPtr9tnvs9XOIiq5jafK2hrGr2qqvJdejmoo" +
        "nlGqWWZRA\"}," +
        "{\"use\":\"sig\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"alg\":\"EdDSA\"," +
        "\"x\":\"FnbcUAXZ4ySvrmdXK1MrDuiqlqTXvGdAaE4RWZjmFIQ\"," +
        "\"kid\":\"q-H9y8iuh3BIKZBbK6S0mH_isBlJsk-u6VtZ5rAdBo5fCjjy3LnkrsoK_QWrlKB08j_PcvwpAMfTE" +
        "DHw5spepw\"}," +
        "{\"use\":\"sig\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"alg\":\"EdDSA\"," +
        "\"x\":\"CS01DGXDBPV9cFmd8tgFu3E7eHn1UcP7N1UCgd_JgZo\"," +
        "\"kid\":\"bL33HthM3fWaYkY2_pDzUd7a65FV2R2LHAKCOsye8eNmAPDgRgpHWPYpWFVmeaujUUEXRyDLHN-Up" +
        "4QH_sFcmw\"}]}";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testKeyJarAdd() throws Exception {
        KeyJar keyJar = new KeyJar();
        List<String> uses = Arrays.asList("ver", "sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", uses);
        keyJar.addKeyBundle("https://issuer.example.com", keyBundle);
        List<String> owners = keyJar.getOwners();
        Assert.assertEquals(owners.get(0), "https://issuer.example.com");
    }

    @Test
    public void testSetBundle() throws Exception {
        KeyJar keyJar = new KeyJar();
        List<String> uses = Arrays.asList("ver", "sig");
        KeyBundle keyBundle = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", uses);
        List<KeyBundle> kbList = Collections.singletonList(keyBundle);
        keyJar.setBundle("https://issuer.example.com", kbList);
        List<String> owners = keyJar.getOwners();
        Assert.assertEquals(owners.get(0), "https://issuer.example.com");
    }


    @Test
    public void testAddSymmetric() throws Exception {
        KeyJar keyJar = new KeyJar();
        List<String> uses = Collections.singletonList("sig");
        keyJar.addSymmetricKey("", "client_secret".getBytes(), uses);
        List<String> owners = keyJar.getOwners();
        List<Key> symKeys = keyJar.getSigningKey("oct", "", "", null);
        Assert.assertEquals(owners.get(0), "");
        Assert.assertEquals(symKeys.size(), 1);
    }


    @Test
    public void testExtraSlash() throws ParseException, Exception {
        String b64Secret1 = Base64.encodeBase64URLSafeString(
            "a1b2c3d4".getBytes(Charset.forName("UTF-8")));
        String jwk1 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret1 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret1 + "\", \"use\": \"ver\"}]";
        List<Map<String, Object>> keyList1 = (List<Map<String, Object>>)jsonParser.parse(jwk1);
        KeyBundle keyBundle1 = new KeyBundle(keyList1);
        String b64Secret2 = Base64.encodeBase64URLSafeString(
            "e5f6g7h8".getBytes(Charset.forName("UTF-8")));
        String jwk2 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret2 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret2 + "\", \"use\": \"ver\"}]";
        List<Map<String, Object>> keyList2 = (List<Map<String, Object>>)jsonParser.parse(jwk2);
        KeyBundle keyBundle2 = new KeyBundle(keyList2);
        List<String> usage = Arrays.asList("ver", "sig");
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
        String b64Secret1 = Base64.encodeBase64URLSafeString(
            "a1b2c3d4".getBytes(Charset.forName("UTF-8")));
        String jwk1 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret1 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret1 + "\", \"use\": \"ver\"}]";
        List<Map<String, Object>> keyList1 = (List<Map<String, Object>>)jsonParser.parse(jwk1);
        KeyBundle keyBundle1 = new KeyBundle(keyList1);
        String b64Secret2 = Base64.encodeBase64URLSafeString(
            "e5f6g7h8".getBytes(Charset.forName("UTF-8")));
        String jwk2 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret2 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret2 + "\", \"use\": \"ver\"}]";
        List<Map<String, Object>> keyList2 = (List<Map<String, Object>>)jsonParser.parse(jwk2);
        KeyBundle keyBundle2 = new KeyBundle(keyList2);
        List<String> usage = Arrays.asList("ver", "sig");
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
    public void testGetEnc() throws Exception {
        String b64Secret1 = Base64.encodeBase64URLSafeString(
            "a1b2c3d4".getBytes(Charset.forName("UTF-8")));
        String jwk1 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret1 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret1 + "\", \"use\": \"enc\"}]";
        List<Map<String, Object>> keyList1 = (List<Map<String, Object>>)jsonParser.parse(jwk1);
        KeyBundle keyBundle1 = new KeyBundle(keyList1);
        String b64Secret2 = Base64.encodeBase64URLSafeString(
            "e5f6g7h8".getBytes(Charset.forName("UTF-8")));
        String jwk2 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret2 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret2 + "\", \"use\": \"enc\"}]";
        List<Map<String, Object>> keyList2 = (List<Map<String, Object>>)jsonParser.parse(jwk2);
        KeyBundle keyBundle2 = new KeyBundle(keyList2);
        List<String> usage = Arrays.asList("ver", "sig");
        KeyBundle keyBundle3 =
            KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle1);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle2);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle3);

        Assert.assertEquals(1, keyJar.getKeys("enc", "oct", "", "", null).size());

    }


    @Test
    public void testEncNotMine() throws Exception {
        String b64Secret1 = Base64.encodeBase64URLSafeString(
            "a1b2c3d4".getBytes(Charset.forName("UTF-8")));
        String jwk1 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret1 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret1 + "\", \"use\": \"enc\"}]";
        List<Map<String, Object>> keyList1 = (List<Map<String, Object>>)jsonParser.parse(jwk1);
        KeyBundle keyBundle1 = new KeyBundle(keyList1);
        String b64Secret2 = Base64.encodeBase64URLSafeString(
            "e5f6g7h8".getBytes(Charset.forName("UTF-8")));
        String jwk2 = "[{\"kty\": \"oct\", \"k\": \"" +  b64Secret2 + "\", \"use\": \"sig\"}," +
            "{\"kty\": \"oct\", \"k\": \"" + b64Secret2 + "\", \"use\": \"enc\"}]";
        List<Map<String, Object>> keyList2 = (List<Map<String, Object>>)jsonParser.parse(jwk2);
        KeyBundle keyBundle2 = new KeyBundle(keyList2);
        List<String> usage = Arrays.asList("ver", "sig");
        KeyBundle keyBundle3 =
            KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usage);

        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle1);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle2);
        keyJar.addKeyBundle("http://www.example.org/", keyBundle3);

        Assert.assertEquals(2, keyJar.getKeys("enc", "oct", "http://www.example.org/", "", null).size());
    }


    @Test
    public void testDumpIssuerKeys() throws Exception {
        List<String> usage = Collections.singletonList("sig");
        KeyBundle keyBundle =
            KeyBundle.keyBundleFromLocalFile(JSON_PUBLIC_KEY_FILE, "jwks", usage);
        KeyJar keyJar = new KeyJar();
        keyJar.addKeyBundle("", keyBundle);

        Map<String, Object> keysJwks =
            keyJar.exportJwks(false, "");
        Assert.assertNotNull(keysJwks);
        List<Map<String, Object>> keys = (List<Map<String, Object>>)keysJwks.get("keys");
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

    @Test
    public void testNoUse() throws Exception {
        JSONObject jsonObject = (JSONObject) jsonParser.parse(JWK0STRING);
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jsonObject.get("keys");
        KeyBundle keyBundle = new KeyBundle(keys);
        KeyJar keyJar = new KeyJar();
        List<KeyBundle> keyBundles = Collections.singletonList(keyBundle);
        keyJar.setBundle("abcdefgh", keyBundles);
        List<Key> encKeys = keyJar.getEncryptKey("RSA", "abcdefgh", null, null);
        Assert.assertNotEquals(0, encKeys.size());
    }


    @Test
    public void testProvider() throws Exception {
        Map<String, Object> pcr = new HashMap<String, Object>();
        pcr.put("jwks_uri", "https://connect-op.herokuapp.com/jwks.json");
        KeyJar keyJar = new KeyJar();
        keyJar.loadKeys(pcr, "https://connect-op.heroku.com", false);
        System.out.println(keyJar.getBundle("https://connect-op.heroku.com").get(0).getKeys().toString());
        List<Key> keys = keyJar.getIssuerKeys("https://connect-op.heroku.com");
        System.out.println(keyJar.getBundle("https://connect-op.heroku.com").get(0).getKeys().toString());

        List<Key> keys2  = keyJar.getBundle("https://connect-op.heroku.com").get(0).getKeys();
        System.out.println(keys2.toString());
        Assert.assertEquals(1, keys.size());

        KeyBundle keyBundle = keyJar.find("https://connect-op.herokuapp.com/jwks.json", "https://connect-op.heroku.com");
        Assert.assertTrue(keyBundle != null);

        KeyBundle keyBundleNull = keyJar.find("https://connect-op.herokuapp.com/dummy.json", "https://connect-op.heroku.com");
        Assert.assertTrue(keyBundleNull == null);


    }

    @Test
    public void testLoadKeysFromConfig() throws Exception {
        Object json = jsonParser.parse(JWK1STRING);

        Map<String, Object> pcr = new HashMap<String, Object>();
        pcr.put("jwks", json);
        KeyJar keyJar = new KeyJar();
        keyJar.loadKeys(pcr, "", false);
        List<Key> keys = keyJar.getIssuerKeys("");
        Assert.assertEquals(4, keys.size());

    }


    @Test
    public void testImportJwks() throws Exception {
        Object json = jsonParser.parse(JWK1STRING);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");
        List<Key> keys = keyJar.getIssuerKeys("");
        Assert.assertEquals(keys.size(), 4);

    }

    @Test
    public void testGetSigningKeyUseUndefined() throws Exception {
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
        Object json = jsonParser.parse(JWK2STRING);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");

    }

    @Test
    public void testBuildKeyJar() throws Exception {
        String keyString = "[{\"type\":\"RSA\",\"use\":[\"enc\",\"sig\"]}," +
            "{\"type\":\"EC\",\"crv\":\"P-256\",\"use\":[\"sig\"]}]";
        List<Object> conf = (List<Object>)jsonParser.parse(keyString);
        KeyJar keyJar = KeyJar.buildKeyJar(conf, "", null, null);
        Assert.assertNotNull(keyJar);
        List<KeyBundle> keyBundles = keyJar.getBundle("");
        Assert.assertEquals(2, keyBundles.size());
    }

    @Test
    public void testLoadMissingKeyParameter() throws ImportException, ParseException , IOException, JWKException, ValueError {
        String jwk = "{\"keys\":[{\"e\":\"AQAB\",\"kty\":\"RSA\",\"kid\":\"rsa1\"}]}";
        Object json = jsonParser.parse(jwk);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");
        List<KeyBundle> keys = keyJar.getBundle("");
        Assert.assertEquals(0, keys.get(0).getKeys().size());
    }

    @Test
    public  void testLoadUnknownKeyType() throws ParseException, ImportException, IOException, JWKException, ValueError  {
        String jwk = "{\"keys\":[{\"n\":\"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7" +
            "H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0" +
            "a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-" +
            "syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEm" +
            "hcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w\"," +
            "\"e\":\"AQAB\",\"kty\":\"RSA\",\"kid\":\"rsa1\"}," +
            "{\"k\":\"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE" +
            "\",\"kty\":\"buz\"}]}";

        Object json = jsonParser.parse(jwk);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");

        List<KeyBundle> keys = keyJar.getBundle("");
        Assert.assertEquals(2, keys.get(0).getKeys().size());
    }

    @Test
    public void testLoadSpomkyKeys() throws Exception{
        Object json = jsonParser.parse(JWKS_SPO);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");

        Assert.assertEquals(4, keyJar.getIssuerKeys("").size());
    }


    @Test
    public void testGetEC() throws Exception{
        Object json = jsonParser.parse(JWKS_SPO);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");
        Map<String, String> args = new HashMap<>();
        args.put("alg", "ES256");
        List<Key> keys = keyJar.getKeys("sig", "EC", "", "", args);
        Assert.assertEquals(2, keys.size());
    }

    @Test
    public void testGetECWrongAlg() throws Exception{
        Object json = jsonParser.parse(JWKS_SPO);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)json, "");
        Map<String, String> args = new HashMap<>();
        args.put("alg", "ES512");
        List<Key> keys = keyJar.getKeys("sig", "EC", "", "", args);
        Assert.assertEquals(0, keys.size());
    }

    @Test
    public void testKeysByAlgUsage() throws Exception {
        JSONObject jsonObject = (JSONObject) jsonParser.parse(JWKS_SPO);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)jsonObject, "");
        List<Key> keys = keyJar.keysByAlgAndUsage("", "RS256", "sig");
        Assert.assertEquals(2, keys.size());
    }


    @Test
    public void testRemoveAfter() throws Exception {
        final String KEYDEFS = "[{\"type\": \"RSA\", \"key\": \"\", \"use\": [\"sig\"]}," +
            "{\"type\": \"EC\", \"crv\": \"P-256\", \"use\": [\"sig\"]}]";
        Object jsonObject = jsonParser.parse(KEYDEFS);
        KeyJar keyJar = KeyJar.buildKeyJar((List<Object>) jsonObject, null, null, null);
        List<Key> keyList = keyJar.getIssuerKeys("");
        List<String> oldKids = new ArrayList<>();
        for (Key key : keyList) {
            if (!Utils.isNullOrEmpty(key.getKid())) {
                oldKids.add(key.getKid());
            }
        }
        Assert.assertEquals(2, keyList.size());

        // Rotate_keys = create new keys + make the old as inactive
        keyJar = KeyJar.buildKeyJar((List<Object>) jsonObject, null, keyJar, null);
        keyJar.setRemoveAfter(1);
        // None are remove since none are marked as inactive yet
        keyJar.removeOutdated(0);
        List<String> interimKids = new ArrayList<>();
        for (Key key : keyJar.getIssuerKeys("")) {
            if (!Utils.isNullOrEmpty(key.getKid())) {
                interimKids.add(key.getKid());
            }
        }
        Assert.assertEquals(4, interimKids.size());
        // Now mark the keys to be inactivated
        long now = System.currentTimeMillis();
        for (Key key : keyJar.getIssuerKeys("")) {
            if (oldKids.contains(key.getKid())) {
                if (key.inactiveSince == 0) {
                    key.inactiveSince = now;
                }
            }
        }

        keyJar.removeOutdated(now + 5000);
        List<String> newKids = new ArrayList<>();
        for (Key key : keyJar.getIssuerKeys("")) {
            if(!Utils.isNullOrEmpty(key.getKid())) {
                newKids.add(key.getKid());
            }
        }
        Assert.assertEquals(2, newKids.size());
        newKids.retainAll(oldKids);

        Assert.assertEquals(0, newKids.size());

    }

    @Test
    public void testCopy() throws ParseException, ImportException, IOException, JWKException, ValueError {
        KeyBundle aliceBundle = new KeyBundle((List<Map<String,Object>>)((Map<String, Object>)
            jsonParser.parse(JWK0STRING)).get("keys"));
        KeyBundle bobBundle = new KeyBundle((List<Map<String,Object>>)((Map<String, Object>)
            jsonParser.parse(JWK1STRING)).get("keys"));
        KeyBundle cBundle = new KeyBundle((List<Map<String,Object>>)((Map<String, Object>)
            jsonParser.parse(JWK2STRING)).get("keys"));
        KeyJar keyJar = new KeyJar();
        keyJar.setBundle("Alice", Collections.singletonList(aliceBundle));
        keyJar.setBundle("Bob", Collections.singletonList(bobBundle));
        keyJar.setBundle("C", Collections.singletonList(cBundle));
        KeyJar keyJarCopy = keyJar.copy();
        List<String> owners = keyJarCopy.getOwners();
        Assert.assertTrue(owners.containsAll(Arrays.asList("Alice", "Bob", "C")));

        Assert.assertEquals(0, keyJarCopy.getKeys("sig", "oct", "Alice", null ,null).size());
        Assert.assertEquals(1, keyJarCopy.getKeys("sig", "rsa", "Alice", null ,null).size());
        Assert.assertEquals(1, keyJarCopy.getKeys("sig", "oct", "Bob", null ,null).size());
        Assert.assertEquals(1, keyJarCopy.getKeys("sig", "rsa", "Bob", null ,null).size());
        Assert.assertEquals(0, keyJarCopy.getKeys("sig", "oct", "C", null ,null).size());
        Assert.assertEquals(4, keyJarCopy.getKeys("sig", "rsa", "C", null ,null).size());

    }

    @Test
    public void testKeys() throws Exception {
        final String JWKS = "{\"keys\":" +
            "[{\"n\":\"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X" +
            "9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs" +
            "5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-s" +
            "yM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfR" +
            "U9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w\",\"e\":\"AQAB\",\"kty\":\"RSA\"," +
            "\"kid\":\"5-VBFv40P8D4I-7SFz7hMugTbPs\",\"use\":\"enc\"}," +
            "{\"k\":\"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0N" +
            "zMzYjE\",\"kty\":\"oct\",\"use\":\"enc\"}," +
            "{\"kty\":\"EC\",\"kid\":\"7snis\"," +
            "\"use\":\"sig\",\"x\":\"q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po\"," +
            "\"y\":\"GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E\",\"crv\":\"P-256\"}]}";
        JSONObject jsonObject = (JSONObject) jsonParser.parse(JWKS);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)jsonObject, "");
        List<Key> symKeys = keyJar.getKeys("enc", "oct", "", "", null);
        List<Key> rsaKeys = keyJar.getKeys("enc", "rsa", "", "", null);
        List<Key> ecKeys = keyJar.getKeys("", "ec", "", "", null);
        Assert.assertEquals(1, symKeys.size());
        Assert.assertEquals(1, rsaKeys.size());
        Assert.assertEquals(1, ecKeys.size());

    }


    @Test
    public void testThumbprints() throws Exception, SerializationNotPossible {
        final String JWKS = "{\"keys\":" +
            "[{\"n\":\"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X" +
            "9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs" +
            "5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-s" +
            "yM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfR" +
            "U9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w\",\"e\":\"AQAB\",\"kty\":\"RSA\"," +
            "\"kid\":\"5-VBFv40P8D4I-7SFz7hMugTbPs\",\"use\":\"enc\"}," +
            "{\"k\":\"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0N" +
            "zMzYjE\",\"kty\":\"oct\",\"use\":\"enc\"}," +
            "{\"kty\":\"EC\",\"kid\":\"7snis\"," +
            "\"use\":\"sig\",\"x\":\"q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po\"," +
            "\"y\":\"GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E\",\"crv\":\"P-256\"}]}";
        JSONObject jsonObject = (JSONObject) jsonParser.parse(JWKS);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)jsonObject, "");
        List<Key> keys = keyJar.getIssuerKeys("");
        List<String> expected = new ArrayList<>(Arrays.asList(
            "iA7PvG_DfJIeeqQcuXFmvUGjqBkda8In_uMpZrcodVA", // rsa
            "kLsuyGef1kfw5-t-N9CJLIHx_dpZ79-KemwqjwdrvTI", // oct
            "akXzyGlXg8yLhsCczKb_r8VERLx7-iZBUMIVgg2K7p4"  // ec
        ));
        Assert.assertEquals(3, keys.size());
        for(Key key : keys) {
            String thumbprint = key.thumbprint("SHA-256");
            Assert.assertTrue(expected.contains(thumbprint));
        }

        Key key = keys.get(2);
        String thumbprint = key.thumbprint("SHA-256");
        String thumbprintJSON = "{\"crv\":\"P-256\",\"kty\":\"EC\"," +
            "\"x\":\"q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po\"," +
            "\"y\":\"GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E\"}";
        String expectedThumbprint = Base64.encodeBase64URLSafeString(
            MessageDigest.getInstance("SHA-256").digest(
                thumbprintJSON.getBytes(Charset.forName("UTF-8"))));
        Assert.assertEquals(expectedThumbprint, thumbprint);

    }

    @Test
    public void testImportExportJSON() throws Exception, SerializationNotPossible {
        final String JWKS = "{\"keys\":" +
            "[{\"n\":\"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X" +
            "9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs" +
            "5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-s" +
            "yM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfR" +
            "U9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w\",\"e\":\"AQAB\",\"kty\":\"RSA\"," +
            "\"kid\":\"5-VBFv40P8D4I-7SFz7hMugTbPs\",\"use\":\"enc\"}," +
            "{\"k\":\"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0N" +
            "zMzYjE\",\"kty\":\"oct\",\"use\":\"enc\"}," +
            "{\"kty\":\"EC\",\"kid\":\"7snis\"," +
            "\"use\":\"sig\",\"x\":\"q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po\"," +
            "\"y\":\"GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E\",\"crv\":\"P-256\"}]}";
        JSONObject jsonObject = (JSONObject) jsonParser.parse(JWKS);
        KeyJar keyJar = new KeyJar();
        keyJar.importJwks((Map<String, Object>)jsonObject, "");

        String exportedJSON = keyJar.exportJwksAsJson(false, "");

        KeyJar keyjarExport = new KeyJar();
        keyjarExport.importJwksAsJson(exportedJSON, "");

        List<Key> keys = keyJar.getIssuerKeys("");
        List<String> expected = new ArrayList<>(Arrays.asList(
            "iA7PvG_DfJIeeqQcuXFmvUGjqBkda8In_uMpZrcodVA", // rsa
            "kLsuyGef1kfw5-t-N9CJLIHx_dpZ79-KemwqjwdrvTI", // oct
            "akXzyGlXg8yLhsCczKb_r8VERLx7-iZBUMIVgg2K7p4"  // ec
        ));
        Assert.assertEquals(3, keys.size());
        for(Key key : keys) {
            String thumbprint = key.thumbprint("SHA-256");
            Assert.assertTrue(expected.contains(thumbprint));
        }

        Key key = keys.get(2);
        String thumbprint = key.thumbprint("SHA-256");
        String thumbprintJSON = "{\"crv\":\"P-256\",\"kty\":\"EC\"," +
            "\"x\":\"q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po\"," +
            "\"y\":\"GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E\"}";
        String expectedThumbprint = Base64.encodeBase64URLSafeString(
            MessageDigest.getInstance("SHA-256").digest(
                thumbprintJSON.getBytes(Charset.forName("UTF-8"))));
        Assert.assertEquals(expectedThumbprint, thumbprint);

    }


}