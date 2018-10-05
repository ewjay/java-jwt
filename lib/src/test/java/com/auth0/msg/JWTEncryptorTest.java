package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTDecryptor;
import com.auth0.jwt.JWTEncryptor;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;

public class JWTEncryptorTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testEncryption() throws  Exception{

        short[] contentShorts = new short[] {
            84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
            111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
            101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
            101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
            110, 97, 116, 105, 111, 110, 46
        };

        byte[] content = TestUtils.convertShortArrayToByteArray(contentShorts);
        String contentString = StringUtils.newStringUtf8(content);
        System.out.println(contentString);

        RSAKey rsaKey = RSAKey.publicKeyBuilder("oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW" +
            "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S" +
            "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a" +
            "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS" +
            "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj" +
            "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw", "AQAB").build();


        short[] cekShorts = new short[] {
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
            212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
            234, 64, 252
        };

        byte[] cek = TestUtils.convertShortArrayToByteArray(cekShorts);


        short[] ivShorts = new short[] {
            227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219
        };

        byte[] iv = TestUtils.convertShortArrayToByteArray(ivShorts);

        CipherParams cipherParams = new CipherParams(cek, iv);

        String header = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
        String encodedHeader = Base64.encodeBase64URLSafeString(header.getBytes("UTF-8"));
        Assert.assertEquals("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", encodedHeader);

        Algorithm algorithm = Algorithm.RSAOAEP((RSAPublicKey) rsaKey.getKey(false), null);
        Algorithm encAlg = Algorithm.A256GCM(cipherParams);

        JWTEncryptor encryptor = new JWTEncryptor(algorithm, encAlg, header.getBytes("UTF-8"), content);
        String jwe = encryptor.encrypt();
        System.out.printf("jwe1 = %s\n", jwe);

        String jwe2 = JWTEncryptor.init().withPayload(content).encrypt(algorithm, encAlg);
        System.out.printf("jwe2 = %s\n", jwe2);

        RSAKey rsaPrivate = RSAKey.privateKeyBuilder("oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW" +
            "cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S" +
            "psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a" +
            "sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS" +
            "tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj" +
            "YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
            "AQAB",
            "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N" +
                "WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9" +
                "3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk" +
                "qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl" +
                "t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd" +
                "VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
            "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-" +
                "SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf" +
                "fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
            "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm" +
                "UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX" +
                "IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
            "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL" +
                "hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827" +
                "rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
            "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj" +
                "ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB" +
                "UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
            "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7" +
                "AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3" +
                "eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY",
            null).build();

        Algorithm decyptionAlg = Algorithm.RSAOAEP(null, (RSAPrivateKey) rsaPrivate.getKey(true));

        String jwe3 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ." +
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" +
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" +
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" +
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" +
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" +
            "6UklfCpIMfIjf7iGdXKHzg." +
            "48V1_ALb6US04U3b." +
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" +
            "SdiwkIr3ajwQzaBtQD_A." +
            "XFBoMYUZodetZdvTiFvSkQ";

        System.out.printf("jwe3 = %s\n", jwe3);

        JWTDecryptor decryptor = new JWTDecryptor(decyptionAlg);
        byte[] plainText1 = decryptor.decrypt(jwe);

        Assert.assertTrue(Arrays.equals(plainText1, content));

        byte[] plainText2 = decryptor.decrypt(jwe2);

        Assert.assertTrue(Arrays.equals(plainText2, content));

        byte[] plainText3 = decryptor.decrypt(jwe3);

        Assert.assertTrue(Arrays.equals(plainText3, content));



    }

    @Test
    public void testEncryptedSignJWT() throws Exception {

        KeyPair senderKeyPair = RSAKey.generateRSAKeyPair(2048);
        KeyPair receiverKeyPair = RSAKey.generateRSAKeyPair(2048);


        JWTCreator.Builder builder = JWT.create()
            .withClaim("gender", "F")
            .withAudience("Bob")
            .withIssuer("Mark")
            .withSubject("Alice")
            .withClaim("birthdate", "20180101");
        Algorithm signAlg = Algorithm.RSA256(null, (RSAPrivateKey) senderKeyPair.getPrivate());
        String jws = builder.sign(signAlg);
        System.out.printf("jws = %s\n", jws);


        Algorithm keyEncAlg = Algorithm.RSA1_5((RSAPublicKey) receiverKeyPair.getPublic(), null);
        CipherParams cipherParams = CipherParams.getInstance("A256GCM");
        Algorithm contentEncAlg = Algorithm.A256GCM(cipherParams);
        String jwe = JWTEncryptor.init().withContentType("JWT")
            .withPayload(jws.getBytes(StandardCharsets.UTF_8))
            .encrypt(keyEncAlg, contentEncAlg);
        System.out.printf("jwe = %s\n", jwe);


        Algorithm keyDecAlg = Algorithm.RSA1_5(null, (RSAPrivateKey) receiverKeyPair.getPrivate());
        DecodedJWT decodedJWS = JWT.decode(jwe).decrypt(keyDecAlg);
        System.out.printf("Decrypted JWS = %s\n", decodedJWS.getToken());


        Algorithm verifyAlg = Algorithm.RSA256((RSAPublicKey) senderKeyPair.getPublic(), null);
        DecodedJWT jwt = JWT.require(verifyAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
            .build()
            .verify(decodedJWS.getToken());

        Map<String, Claim> claims = jwt.getClaims();
        for (Map.Entry<String, Claim> entry : claims.entrySet()) {
            System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asString());
        }

    }
}
