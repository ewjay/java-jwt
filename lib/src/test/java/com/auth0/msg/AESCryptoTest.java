package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTDecryptor;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.AuthenticatedCipherText;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.JWEContentEncryptionAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyEncryptionAlgorithm;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

public class AESCryptoTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testAESCrypto() throws Exception {

        byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(Charset.forName("UTF-8"));
        byte[] iv = new byte[16];
        byte[] key = new byte[16];

        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        secureRandom.nextBytes(key);
        System.out.println("Data : " + Hex.encodeHexString(data));
        System.out.println("IV : " + Hex.encodeHexString(iv));
        System.out.println("Key : " + Hex.encodeHexString(key));

        CipherParams cipherParams = CipherParams.getInstance("A128CBC-HS256", null);

        JWEContentEncryptionAlgorithm aes = Algorithm.A128CBC_HS256(cipherParams);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        String header = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
        String encodeHeader = Base64.encodeBase64URLSafeString(header.getBytes("UTF-8"));
        byte[] aad = encodeHeader.getBytes("UTF-8");


        AuthenticatedCipherText cipherText  = aes.encrypt(data, aad);
        System.out.println("CipherText : " + Hex.encodeHexString(cipherText.getCipherText()));
        System.out.println("AuthTag : " + Hex.encodeHexString(cipherText.getTag()));

        byte[] plainText = aes.decrypt(cipherText.getCipherText(), cipherText.getTag(), aad);
        System.out.println("Plain : " + Hex.encodeHexString(plainText));

        System.out.println("Original : " + new String(plainText, Charset.forName("UTF-8")));

        System.out.println(header);
        System.out.println(encodeHeader);
        System.out.println(Hex.encodeHexString(encodeHeader.getBytes("ASCII")));
        long num = 1024;
        byte[] AL = ByteBuffer.allocate(Long.BYTES).putLong(num).array();

        System.out.printf("%08x\n", num);

        ByteBuffer byteBuffer = ByteBuffer.allocate(encodeHeader.length() + iv.length + cipherText.getCipherText().length + Long.BYTES);
        byteBuffer.put(encodeHeader.getBytes("ASCII"));
        byteBuffer.put(iv);
        byteBuffer.put(cipherText.getCipherText());
        byteBuffer.put(AL);
        System.out.println(Hex.encodeHexString(byteBuffer.array()));
    }

    @Test
    public void testJwtEncrypt() throws Exception {
        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        Algorithm rsaAlg = Algorithm.RSA1_5(rsaPublicKey, null);
        CipherParams cipherParams = CipherParams.getInstance("A128CBC-HS256");
        Algorithm encAlg = Algorithm.A128CBC_HS256(cipherParams);

        JWTCreator.Builder builder = JWT.create()
            .withClaim("first_name", "JoHn")
            .withClaim("last_name", "SmItH")
            .withAudience("JaNe")
            .withClaim("birthdate", "20180101");

        String jwe = builder.encrypt(rsaAlg, encAlg);
        System.out.println(jwe);


        DecodedJWT decodedJWT = JWT.decode(jwe);
        if(decodedJWT.isJWE()) {
            byte[] encryptedKey = Base64.decodeBase64(decodedJWT.getKey());
            byte[] iv = Base64.decodeBase64(decodedJWT.getIV());
            byte[] tag = Base64.decodeBase64(decodedJWT.getAuthenticationTag());
            byte[] headerBytes = decodedJWT.getHeader().getBytes("UTF-8");
            byte[] cipherText = Base64.decodeBase64(decodedJWT.getCipherText());

            JWEKeyEncryptionAlgorithm rsaAlg2 = Algorithm.RSA1_5(null, rsaPrivateKey);
            byte[] decryptedKey = rsaAlg2.decrypt(encryptedKey);
            int mid = decryptedKey.length / 2;
            byte[] encKey = Arrays.copyOfRange(decryptedKey, mid, decryptedKey.length);
            byte[] macKey = Arrays.copyOfRange(decryptedKey, 0, mid);
            CipherParams cipherParams2 = new CipherParams(encKey, macKey, iv);
            JWEContentEncryptionAlgorithm encAlg2 = Algorithm.A128CBC_HS256(cipherParams2);
            byte[] plainText = encAlg2.decrypt(cipherText, tag, headerBytes);
            String text = new String(plainText);
            System.out.println(text);
        }
        System.out.println("\n========================================\n");
        System.out.println(new String(Base64.decodeBase64(decodedJWT.getHeader())));

        System.out.println("\n========================================\n");

        decodedJWT.decrypt(Algorithm.RSA1_5(null, rsaPrivateKey));
        System.out.println("\n========================================\n");

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


        JWEKeyEncryptionAlgorithm rsaAlg2 = Algorithm.RSAOAEP(null, rsaPrivateKey);
        DecodedJWT decodedJWT = JWT.decode(jwe);
        if(decodedJWT.isJWE()) {
            byte[] encryptedKey = Base64.decodeBase64(decodedJWT.getKey());
            byte[] iv = Base64.decodeBase64(decodedJWT.getIV());
            byte[] tag = Base64.decodeBase64(decodedJWT.getAuthenticationTag());
            byte[] headerBytes = decodedJWT.getHeader().getBytes("UTF-8");
            byte[] cipherText = Base64.decodeBase64(decodedJWT.getCipherText());


            byte[] decryptedKey = rsaAlg2.decrypt(encryptedKey);
            CipherParams cipherParams2 = new CipherParams(decryptedKey, iv);
            JWEContentEncryptionAlgorithm encAlg2 = Algorithm.A128GCM(cipherParams2);
            byte[] plainText = encAlg2.decrypt(cipherText, tag, headerBytes);
            String text = new String(plainText);
            System.out.println(text);
        }
        System.out.println("\n========================================\n");
        System.out.println(new String(Base64.decodeBase64(decodedJWT.getHeader())));

        System.out.println("\n========================================\n");

        decodedJWT.decrypt(Algorithm.RSAOAEP(null, rsaPrivateKey));
        System.out.println("\n========================================\n");


//        JWTVerifier.init(Algorithm.HMAC256("secret"))
//            .withAudience("nope")
//            .build()
//            .verify(token);

        DecodedJWT jwt = JWT.require(rsaAlg2).withIssuer("Mark").withAudience("Bob").withSubject("Alice")
            .build()
            .verify(jwe);
        Map<String, com.auth0.jwt.interfaces.Claim> claims = jwt.getClaims();
        for (Map.Entry<String, Claim> entry : claims.entrySet()) {
            System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asString());
        }

        exception.expect(DecryptionException.class);
        DecodedJWT jwt2 = JWT.require(Algorithm.RSAOAEP(null, rsaPrivateKey2)).withIssuer("Mark").withAudience("Bob").withSubject("Alice")
            .build()
            .verify(jwe);

    }

    @Test
    public void testDecryptExternalJWE() throws Exception {

        final String PRIVATE_KEY_FILE = "src/test/resources/jwe.pem";
        RSAKey rsaKey = RSAKey.load(PRIVATE_KEY_FILE);
        java.security.Key key = rsaKey.getKey(true);
        Algorithm rsaTestAlg = Algorithm.RSA1_5(null, (RSAPrivateKey) key);
        /**
         * JWE contains payload :
         * {"iss":"Bob","sub":"Alice","aud":"John","exp":1536694345,"iat":1536694045}
         */
        String jwe1 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ME7vaS-h_2xq5Rq5FZBrZN" +
            "gWMRuF_eMgCUvex6RonQhsft9PVVyShP89IZq9vrjqHassX0wy59a8vCAKzjSDoVZgHOwUazeH06lU3yac9" +
            "5yN-6BGUGRD6X91NcIIGbMEORjrD9gaI_5Z_obEnRYtQXWfexYfKyJnThdJS0SUWhneoWWjiff3fu4ZzuEY" +
            "fYtJqS-XefDvDYcSXA7Yq2sjVcIPBE_wNyEy9BGKr4WgPuU6_udvowRwsMYDBHJ3Wu6FCkIczPW_4rERKzO" +
            "PmT5v0eHou3vV2Ui2YVU5_l4d_DawUUOfJkNSEZ5CsiP1S5MizHg9461S1DsPv6vpO38R4Q._A9YV6pOLlq" +
            "OocVsZZzcXg.0IADTO0lwqa5QmXtTLfaC_tgpItOLYOL2zY8oG46Y_W40Iyu5gFg-Ch846yc51ZOW--4CJl" +
            "3e8P_k7ekGr7tA8rr0MjbYW1QEwbugjtYyCc.bDwLbvqoAw3AE4LnKLCBwg";



        String[] jwes = new String[] {
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.lHMIWytvHY1xaerQ9YDQmHp8NgNt5h0U0fnQfIAJerrRoHY3G6xmXF97T8UQOF_IeFcfNW9evKmkutNwmVcGsErc9kIExoERqj4d5f7MOmNQ9WcwrLln8TyAcM1l0SCJpffkY0rB7vpLwZ2n_XcZdfUGbOY2xjprj0TS7qSICJd4in3wTT9HX3K1k-7xota1slQKMMPftXGVECXnem12liezflNpPb03qC6nJVihnOa7R91-wlRo6onCdnJ2GYdDD1ucX6YdriMsanJRs1qpDDtXLKy1oJqhps-tLWlR8S6I_nIIaOhr7JHuALZ2kJHfG1Rukv3AQJUEXDC_B07aFQ.1WDdw6Eg-9uqRU3qEobofw.T5356SCyWaKS7fYKnRZ9fnkSvWcOOJqYN38Zbwe3ZyAvPtLBHfJ-IkBsie-D9i5F4iYVWqLmGP21vIkXzasq5604m8LH9emUZVXAPY3N3WQ.ST54UX-YYOUyIYT4q014mw",
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.a2kBIUurycZMDtW-C5FyV6bHBuW21CXJ9kn9-2Ccr8SN70r_f-VT06PR41SbN1tOnU5Pt1xvCumRoBTG7rf1Bg3fzv8BOeBn3CH83tfcqBogdd8kMpdCo7v0knHcuyd7ZMmSjcuCfDDpsD69I2e7iW0_lSBbsjaIf6zFkk18IH-xMxcZbrgkhRutHze7oAFb5mhPV3GTW_GP_Poo0AZ11GXznzr_cGz4DRkXRY-uGMVv9dXuqmddVtOfprUAs8dXM-mSXwra27C9fHOW67LHL0HK9qYA2y3jdA_6yYbJ-2Z0nihKMAfEfGEuWp3BWWzk9gcbSNdGIMBVso42c7IqRQ.L-TERcnAzoFxVwkyXP3-_w.LsO_BXED-c7pioH0ApUpRHARCWdW2HPm_Q4wRPdgxbCSCIRdbM67d8eYjBM5OZJMK2BZQfC3kpCioSQse5uhzQLHOe7Cn5wy7fTQ6_oc4Ys.7wzbMTgmcyN1YkSv_xZm4RZcgNCWfTEl",
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.ABzEA8ma8WKLx1HrGinWN7aao1MPmvjqReeClCeWCZBT-Cpl8XQXXDK9p6PX23vhbrm4zVsTbMpvr0umLhIkIYUbwag6OrTljnjKtReFGG1krwbZMD7FDXVi85BVff-bLmlkvUZfoUQ8C7riU6BZC5mZin8E3oCuMHFxDBDYZtV5y646Js44RvwvOmt4yTmDdtmdXGChBlBWxEztZkgDm-0Ge5STrjwaS-pQ-4qHCEylwZcoYsMGj5Wv6fER6MuK1aVriT-vQ4I_AsGKpYPsvMFG3GvnYxhiSvQZ8dWzQ3wXlTitbX8wMzi8vWZUqnaRqJaFmeBiEeKoPjxi1sGZDw.35GhIbcZ9LEnR4ovFS2NFg.6OzBcG1Wf7UasI7lskNRZGW0gg388whO7pTwxzTu1MVECNXl2rvKCbBxBtpwxxEQCkC5Pey8Iip05zbgt1OpBcLmLJjzyOxEFp4Ums1rt0I.adlWnUVoyqUovbqO8AfNjfEwQwnndZujX2bETKd13OE",
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.L03sFF0gucwHlgybpHG5Svv_OVW4R2E1NZ1sx0S-AueCgxAjLRtQWpO7q_lb4UpWFyttIbT-sSqQf3QMr7YEpb86WXaloypBFWSHB9mGilNkRq_uovxXS1df3e8VG_Obg-3TyHbJ4xA5uDCvlBIe2Y1xoXgL3cLBuJnQUDMjE1iUMAEOycEoxeMuYGFCjj28xUZ63OoYMP7E1QGnWl8mjHp3-B33m6aFo86JXaP3hMdyGHiTxiKcGKfR85oOSi0iWYJubRNa5SoH-brNJNpNqUyIBDL0XylDUqbnS7TFXidKxzdQINFvv72fVA_hpmH4CvXdol5o54a8DiXvJmkrew.iQt0hhc8HyMiH_MY.I1SKpr__y5Vn6PHi97leL_bRZ5fpD4_F3nxibdlY3dvB3nUEQsMDNC3qoeUA5IB3nu5Q8iJs2Ur4ILGePmGbaaCy3-FtD0_4Zmk.JEkTUAUB2_YfmFAZSjlCxg",
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyR0NNIn0.TwEYsqIP_VGZir0lcTQhGIJUprHmTfMsSQI_tb28HSqLAsEvnTERjePuQbUE__HsU8jN-w-uK2FXx-SRPIfqvCazq9Kli7aJ61qZNtYNj5OTKwhNhnT7sBC8S4J0QYADGINH2XtZLqsY3mxGd5UkIda8d-IJFVnqI23mECVjsJrM-nZfFz8OeirROBZzs8BPblTm7S_z1RNlxIpOFchKxRxUDLEtW55rHFvbn24tCfJVGXqQ2-05renJ30JcdHZHIcf1Sbi4zxhb1kA0syKyzV6p502xEyBatObK7554DPX2rBmKbFYxjeeec2Lgfwqu1_qbI1OQfyA7esc7G6oDzA.WwTadO3Y1mQ1AUWe.-_c_ZVa2g0s6e_RiBHEgIi2k9K5MzpqWxtnlYyKuaZQzzCEvrrZg7C4fDOFYk5ud_2lTwcaxCOh2ezgjmY98Jn0y78HQNBt9kqI.VZZFTZYQLKfhSnN2Af7ogg",
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0.QAVePVLelquog5adT-3mOVuN2PkqkIzV6ndwX7YlaLhKCc20H9Fp0q6JScHkHbWOuOYGhePG5IcD0o3bJRvIiL53KC34xiF_J2a_tXG2tR2Fw8HYGrVy80Sat_3bRoxEbadcjjfyHFi-MB1LfRrhdncq5koODTMsLewlOu3On4WpExJAMr4O2khjfIpVjI6ydk06oDPKrSmz7EIVgxNdHuuf_p9YVucshP2apHUn7CqhK8EXrOp_fNtaDXmx3fDivh1sa2qMnwwBY6Zv1rsr3xMoMPGoBt5o7wq6G_hXMEIQ_Lq5r4rDJuWBc2zbp7LEwk-he7u6gwFYtw8a4vjVQw.tjaoCwHKBUHszpHs.n3uWqxuv5cXFN2FRoj74HM3rRZ84ls2qVPw-1hoOvUmrHFCIzOsxj2pZ6f5z07aSgDaTeNQhEyrswjxUMhXMPhm9C9PAa7wLdu4.R-prEeeKYvIuLVP7JP8MtQ",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.FlRG3YB51J6W3pLcpA-k6ZZAlzOjppAkECceHeF5z5lnvPgxiFMBKjfJZWfYPEDIiw25gGYDCLKJH8Nogyu3VLBQe3e5_yECiwsw9nM-9emO68vjdjnoxixsJDofCzS_yxmTHrSOdtAGKnGfdojd7-ZlPC5UQ4Lwwsu7HbB9b3X_9TQMZL8SS1IkQxe9QSxArtZGZFtjZwrAglusa5cuFastorLfOdtK7mBwJ5SKeW9Kl4xQZ6cZk852t4k2oCT0zmn_fZIL7n-_Nhu6DS_m7jTglSolu3ejrzkcN5JgLVaoha1l2u8OBKAHT2vp9W4OPY-FFPfNG15ea7kqnpEZ_A.ATIe6266XC_exQZRbOgSvA.lbd3OLERlzIDmMNlZrBSRsvElQW8IdBqwzjv87L8QEHcHOlZbMCGuhsZL-tmcN4jyX_1bV7Z51olVKsq4HcAkPY_onapEhKadtLMnNBAWRk.-htX18tF1wGqrazvVnWpvQ",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ.F34RS3Bkb8bdPQiIYmapSd2FN2j9QWsOpX7kc9-K2KebIueJxJbGjTvx0STA_F8bJBE_W-EEBpCvuuYaIklWHhH3oaByh9J-yPvp1_ijqrMt08lk37q1dv2w_xlZVodYN473ved6RxoyADEVRetMkI31Lik7oEFq_gyohlBh2NuM6l6l8Qdp4Vadhrk6a_q6eeAtJDB2f6joZFKDDwfxjjYSIjJx_vo0q1ICMx5dABhXcskREifotBuI9svQ_g-C75SD0HvxOKfDmRovZKQ8s06XoSCKBePyKUWzzykiqrTOUh5nF3mTjSGBvKThqwXlDIq5pBvr76D0GvswtmAW2g.QYbBvl4vL91EdjF0RqD-ag.P-nLqg-Wu-RnMUJ03iShcvXqwLrZtSSfhaCC_xXpIwlIC-z454m0_k123mU6KzcWULShZuTls17ssdn1PSfu49hLAstfZH6UygkG4OVCUNo.x5KApLfFOvQGivYGeP4UJAPRg7p1EFKj",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ.AQCbFGz0RuUUXK5m_9goqvMwQ0Gn2xlKwJEDn5mJZVVBrVPWKhPCL1u90jr1iHoQe2FaQRRNHsLeisN6Ktv__Zd-HqGDHl9YHUbn9uOHYkLCAinH5IccEFMXJBkkB8fdlTxlOMi-8bK2RiX5D4ubn4ClpfCJMMM1gyZaCiABGSelZjBVtmcdYjdT0LQeWHNoUhVQWbHFCoKbDFEW5cZ8lve_MDvCpNhE2HPsmFa0yRwCzyTVCY3mGySNFebmeT-HHaOLYGTR3zkigLYNYTP0YvbxnA38bf7hvdF7584vtliflwiTAhA3zYibbn_JsZGpMRrkfz2fxznbdhRQCfRP6w.Dbma3ZKJJ9CXEjPVXEgbNg.12uUxjmZkJrGD4v5NmV_bjRZR9E8MHx-C38BtUZi56rzAituTqB9Il6kzS2k3UX4yaGN17x-2D_N4wfQlsT1awq8NoJETSV-s6Dq7ZOzJ-c.dG9OM3dum1We_807SGr-ETUfjl_K-MZzPcXkHxUWVTM",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.fCC1BFdLvtEszW0Dv04KuAlDB4NragiYJbyARf6GRkbfUjuW6U8s4bwryAoOJL1HyrZbVYqa8LCMERQlhLdRG--x5-icuPKuG7bYYFKcsOrDpIgSgsMj7szkIrQdOzVk2c-sK_yJAt-0i6mUd7JQ4DnOnfjuhBEOIjMV2cd0rPkN8lWcIImr5MMF79HmFa0CshxCnt5qlb3ZJ6m1mXHv-Cgr3ZI9eL7KdtTSoQRYbV3Y8wSPbPhHautta_LpAlvdeiaXpIHZs5Tpw36gbI0I7LEO2mGZvJhJNjLhB8PrpnGqfDu17vDakfSmOzMIJhY0GMoc1pqAYkhlLplLt5MyvQ.nDJlYMy3mSp2kcuD.sJPIIXdMd_lmegCUv_JodrvYGuvT60tzuTjLWw6Ca-s5OmuVaL83KhUvXbLpeZQXFzweFwCD9RVLBr1QTFm5463WslE6m8w-u8k.IsC7jV0cN0WEvPvNQwQd9g",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJHQ00ifQ.eNOmubQcq14BqI4dm_9Mr_YUL3EH3xmf_LZFWG00GczruCQ0ride02sXv_xE450kuDJonT4ppZ585c_OB-x-p9tTGEVFAwxYWpVvQnaCevuRzDGkAi6UDmG-7fL6t7D2E9kO65m2t7TFTuIpYnUSyY5PatezE9nAgMEonKMSZQnL-Scc-GPyjU2IaejZ2sEO54BFgNpgIps1slxMNR7aZ2c-ujpUi3mn30Drcsh5Rtkkn5dYVBPwOCQ-ihSu1Y8lHKEdup5oxtRDlXpGS96xpR4R83Z2v53TVMWjoGuiiDn1OLY_mzTCJdK_tw_trfci01tt0uVqTAK-8OmvpDjTXg.E3dZ4SwpUwghBBjj.iIFub4MhGDXFLlwZ36Nq3dmkCdqTn82NWC4gc6IMJ1mM-JmkYnYCeFsnZlK73IfU7t0Gu-JQyrGNjWsPLkhkx-jNPnXbVFT-dG0.HCreJMnZK8lQa2qYgLq5qg",
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.iIWSQWboBNjvPeCrc1BsnNYf9TBQn9XISOInWR0Y3FGFj8-CRyxeUymWqL2dUIH3gBONOQ6VzfSbgsC6XP-I2VlaZg4BKfMi8Tu67lTIwNhD0qVc30yOpspj8TovwV95GRpYugFqxxBbDD4m8ONshv39gYSN72Yb8UwgphZV_UqqfGfAYT_rLsA0-4DbYf-F9916lYN7BBpyQVFPL02TftYPC-IczWKEnTpO8_0UybPVqBLzC1L8sXwL_SibGNMf3qu54FLUATI-kXmveM-0i9ahtfNwrLv1k6I4qD1WRdVxABFchSZQapMmiu_ldgpLLoHIYZh3zl8RzoITJjXxLw.7fApA9xvR97NLjdp.n-Qrg57tIprK8oZtYvKVJQRBUrGej9hBhyWLQLURifT1qO8JOqNn3RwDT5HV7IUiCHlcmsD3eJUHbrjQmQTMJ9CKJ8wPNfhrkX8.dLe1b09ANYqovuYOCKDkmQ",
            "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.kBbmmdz3kUL_PFQ5JirsEgQzWXcMiIkDbjRjcXDimSD2MIB3hxg-9zo7JAf-u2IIbq-QbVKtBpVdMCbvocsyzhNXVkcJiUjP4irQM6F-jA0eXa_SrExOOLhx23sRStcs1W9PKgEo4HcYbiUkM8xLhB_8hYDnj4Uxu94nAGHD7iZrua-bw-vZ7GP-fEuqvO38z3iZWDyqfj8YYny9ZPFOxM9ZQSZReJOZeNOFTtuZRei-WY5vu-L6-rUHPvZjhuCH4J5sTqrJ0g_KSbGjFrsbY6EJ_KJm5hqKWm9nsgL4Pq7g_2MGgawCHFI79l360EAJ9O0Pu9YTPN63m5LSHewu2g.1l1FY8Lnshtix7WxOLVjzg.s8CpZhAUlFWD2MEuc-q0yeGukaXMwMwq0to8A4ci7Ts899TQRwTP8aoDeBrLhi7uum0FDRcO2KdzovcxZIr6-3W1uEQnROCkuGkE0qmRAYA.HMXTeZFEmCkLRzJLebqfpw",
            "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.LYbhOZfDnxLKXc3p2dP2OVgvsJKnaU23sS-GT7zDCByBWxnXDPVlhZ1i1wsKmWi288e_-cZR2iIA1fpPk4Qt2f5KBwCxoEwTGXf5YtvIY-Oxf4Fcs4-FTHYfxvpUl0xkM9SHmTUBjrYjx6MFFa61dOAOH1ouvsXBMHCVBmhEuDcpYUeLapxTE2RDifI9ZbfKxkcVRoWw4YeTHkGMZuFRBUARnIplfVN1xuGZgWBp66Caj2zkBstlqbJEVMtkfkUyI_ygrMcF8XBijaCPBL7LrwtJoxfCrAdAtRUViL-tdnh_9W4Lz732acfGo1VqPpRAQLpUJYflDtuvCqRA8BCndg.V1Ah2txu6W5Ac9dtmCJREw.lr3gjHs9o86N9JFu15nAjH2PgzSH-GWrAIAtRFdzeDTsn6f5cQj2Sa5JuHJSyixLuckcrK7anvTbVylMYQFBU4udjuNAEnjvsTezwiM5huE.8GLnHbeZT6lmIpS7VuW1p8AVNG2hux7F",
            "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Xj0Pqz2Nb2_FXpOn_dw9x9uCcaEo8YC6PRASpUXxHzlOTIHPDyFsQFGWcjlCOHn50DkCGwixtLg-GFkywJdc5WCoF5K0VipdGZ4FC0gxAdGmZaw_YWQxx5RvOZt3q7cAAY8psqbDFD96PVDwyrv0ISwUQldgmBCa-MCApQN_qcHbwEDgvpoJANFDPyEa8aDYTU3lI9Jot56cMnVLpcFxg7BHZiwRGYUyt8SRoWjTIH9kR44SzdK2W96ybEviYxxp6oZt0Bpt_HaaEc8Gk7ujSeCAt2b3HyngmUQ4BzYqI2BdC2GreSax1S-cplU_ghiFzPA1MdDHTx9fUSB6JWBU1g.c4ADmvtnS-MY2j_xCtuPzw.A2alBGQ6ZGcu3azVUx6xVuEZi-naX2fz9RT-vjjwJqdlEwbmnZgVX5MzAtvLUNd8iH-ZnbZQ2_YZ9P3GI-Tk6OrvSGOLeDrP2gwMeTJkL0Y.g7dtpBAQ_-m1JCmbJh8WkLKk9--zONAp4cgh0JY-5hQ",
            "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.Ndffzly_J2017KdsYbUX0XAJXQBNZmqe4MDHSyRni0pWERC3ymhz5uhawaWxOfNsEKCC7qczv0Rci_hNL1mbqRsP0ydxVmsaQszGiJfdgllS5PfsFXuP1jEy8BMreYCrw_Ow4qRkzrZ7vkhSaxUS6sDGDt4H_DGEbRxV7gCxxzscTAPP9tAdkZBEHkfU6ZFDHbDS6TmGWTHAZwu7YWmyLPkQzLyS_kVoJLKyLkDodlxF1tA6HlxWhgDHPmOGUnn0bZB09UiVXBPgIUnS6TfjxaBrvvnNiqSB7IwDAkHJbrBSOGEC6qvyBFqPmYgw3k4T5fVDduP-rFvf-LeoCH8Jjg.HBj2jSW0XsLllGXC.8euy_9SZp_BRmoR46Y3sbSu3lEH4XSnEf1DVG1u962dpcW_WP9wnUbIHP5XDIx-4IpRv4lpspDJDBCRZwg1uouZEC1l7l0OxwBk.LUFoUDLPwW_rjn5b30Na5A",
            "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyR0NNIn0.An64PdSLXkd34iWNGU70-ZUoyXV6bIP-Uy_rJFto5Me8LM_xBOSoJWLlsbynbjfyMierroHDKcMNamSs4fkL-5JT5uWIHBT7AQ-bLCY16egcgMvCHvUyDC12Yt1WV3TQ18TG-us2T4lY-u1pQCWB4CpbzY_XRRnd42kek_U0JwQAVL8ygXdzKGan5UxZyUmKmJyUcQ0J30QmlmkOZQRadk95wdYuKI8SKFDfn3c8i0V8dNXdX9zgTNmlqgXQpToCiQ6e3ocQXY3nVeeI63jja18yC4XdUvlkVEpNsDA4goOhw1M0BuZjSERogDH8gCYhiUlmPqzzU962z7CSghVCFA.rwYM-dfcn-6pdpHa.yqwybYIEmpcYjOyuriJPPL4lPEAeZSsSVRaU2Dc3ADFf1Jy3UW27qBOX_E3YZZT-7OK0m1fBAzCGCWItFL_5RBvKUSAMPK02Ug0.2cQOntOcnTE4udVQg8vegw",
            "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.aK9kSgo3kvlAOdf4qoi125qRrxZWLHOYsrpQ05VBVzp-m5EdK0groM67trQBvFjpN0Qf0nb9HeJ5fb1qhD8QfvicTXRcKCyJe4Svh1HPZEgebuDpDjfnYUdBiMsDYeJxIiwqRo0yggekMC0wioJ7dEu4w8C27_SOCFOA3WzdwnExaUEsGuS80i6xrhV5Oaxa4s8wU1EJsvKFBTcvAbEJ3LpW4wNSkgx89QC1v5zK8eUGL3kQ_FNMqG4u4Qzq05rFFpr8iG2KmnrQO8eH3LeaD5Q4hhIfB7OJgKwH6_m1MblHTaOhBGJ-metTk3cJ9KOFte5oYA7BMYf2LKZA2kovZg.ijCmSpPww95a1VNL.-HwJsCoqqTlHzTw6NzlaWfhu-MDZGlqEZNFopUXEiLRGYZUvvGeBnUHRpCyFfT6qzBUIlv_mlRi4tgbG44Rgj_nNcznLdhn8glY.97gv9rwSC67GsTYvy8ovKg"
        };

        for(String jwe : jwes) {
            DecodedJWT jwtTemp = JWT.decode(jwe);
            String alg = jwtTemp.getAlgorithm();
            String encAalg = jwtTemp.getEncAlgorithm();
            Algorithm rsaAlg = null;
            System.out.printf("%s %s\n==========\n", alg, encAalg);

            if("RSA1_5".equals(alg)) {
                rsaAlg = Algorithm.RSA1_5(null, (RSAPrivateKey) key);
            } else if("RSA-OAEP".equals(alg)) {
                rsaAlg = Algorithm.RSAOAEP(null, (RSAPrivateKey) key);
            } else if("RSA-OAEP-256".equals(alg)) {
                rsaAlg = Algorithm.RSAOAEP256(null, (RSAPrivateKey) key);
            }

            DecodedJWT jwt = JWT.require(rsaAlg).withIssuer("Bob").withAudience("John").withSubject("Alice").acceptIssuedAt(1536694345).acceptExpiresAt(1536694045)
                .build()
                .verify(jwe);
            Map<String, com.auth0.jwt.interfaces.Claim> claims = jwt.getClaims();
            for (Map.Entry<String, Claim> entry : claims.entrySet()) {
                if("sub".equals(entry.getKey()) ||
                    "aud".equals(entry.getKey()) ||
                    "iss".equals(entry.getKey())) {
                    System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asString());
                } else {
                    System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asDate().toString());
                }
            }
            System.out.println("---------------------------");
            JWTDecryptor decryptor = new JWTDecryptor(rsaAlg);
            byte[] plainText = decryptor.decrypt(jwe);
            String payloadStr = StringUtils.newStringUtf8(plainText);
            final JWTParser converter = new JWTParser();
            Payload payload = converter.parsePayload(payloadStr);
            Map<String, com.auth0.jwt.interfaces.Claim> claims1 = payload.getClaims();
            for (Map.Entry<String, Claim> entry : claims1.entrySet()) {
                if("sub".equals(entry.getKey()) ||
                    "aud".equals(entry.getKey()) ||
                    "iss".equals(entry.getKey())) {
                    System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asString());
                    String val1 = entry.getValue().asString();
                    String val2 = claims.get(entry.getKey()).asString();

                    Assert.assertEquals(val1, val2);

                } else {
                    System.out.printf("%s : %s\n", entry.getKey(), entry.getValue().asDate());
                    Date val1 = entry.getValue().asDate();
                    Date val2 = claims.get(entry.getKey()).asDate();
                    Assert.assertEquals(val1, val2);
                }

            }

//            Assert.assertTrue(claims.equals(claims1));
            System.out.println("\n\n\n");

        }

    }


    @Test
    public void testEncryptDecrypt() throws Exception {

        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();


        String[] algs = new String[] {"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"};
        String[] encs = new String[] {"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"};
        for(String alg : algs) {
            for(String enc : encs) {
                System.out.printf("%s %s\n==========\n", alg, enc);

                Algorithm publicAlg = null;
                Algorithm privateAlg = null;
                if(alg.equals("RSA1_5")) {
                    publicAlg = Algorithm.RSA1_5(publicKey, null);
                    privateAlg = Algorithm.RSA1_5(null, privateKey);
                } else  if(alg.equals("RSA-OAEP")) {
                    publicAlg = Algorithm.RSAOAEP(publicKey, null);
                    privateAlg = Algorithm.RSAOAEP(null, privateKey);
                } else if(alg.equals("RSA-OAEP-256")) {
                    publicAlg = Algorithm.RSAOAEP256(publicKey, null);
                    privateAlg = Algorithm.RSAOAEP256(null, privateKey);
                }

                CipherParams cipherParams = CipherParams.getInstance(enc);
                Algorithm encAlg = Algorithm.getContentEncryptionAlg(enc, cipherParams);

                JWTCreator.Builder builder = JWT.create()
                    .withClaim("gender", "F")
                    .withAudience("Bob")
                    .withIssuer("Mark")
                    .withSubject("Alice")
                    .withClaim("birthdate", "20180101");
                String jwe = builder.encrypt(publicAlg, encAlg);
                System.out.println(jwe);


                DecodedJWT jwt = JWT.require(privateAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
                    .build()
                    .verify(jwe);
            }
        }

    }


    @Test
    public void testEncryptDecryptWithDeflate() throws Exception {

        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();


        String[] algs = new String[] {"RSA1_5", "RSA-OAEP", "RSA-OAEP-256"};
        String[] encs = new String[] {"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"};
        for(String alg : algs) {
            for(String enc : encs) {
                System.out.printf("%s %s\n==========\n", alg, enc);

                Algorithm publicAlg = null;
                Algorithm privateAlg = null;
                if(alg.equals("RSA1_5")) {
                    publicAlg = Algorithm.RSA1_5(publicKey, null);
                    privateAlg = Algorithm.RSA1_5(null, privateKey);
                } else  if(alg.equals("RSA-OAEP")) {
                    publicAlg = Algorithm.RSAOAEP(publicKey, null);
                    privateAlg = Algorithm.RSAOAEP(null, privateKey);
                } else if(alg.equals("RSA-OAEP-256")) {
                    publicAlg = Algorithm.RSAOAEP256(publicKey, null);
                    privateAlg = Algorithm.RSAOAEP256(null, privateKey);
                }

                CipherParams cipherParams = CipherParams.getInstance(enc);
                Algorithm encAlg = Algorithm.getContentEncryptionAlg(enc, cipherParams);

                JWTCreator.Builder builder = JWT.create()
                    .withClaim("gender", "F")
                    .withAudience("Bob")
                    .withIssuer("Mark")
                    .withSubject("Alice")
                    .withClaim("birthdate", "20180101");
                String jwe = builder.encrypt(publicAlg, encAlg, true);
                System.out.println(jwe);


                DecodedJWT jwt = JWT.require(privateAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
                    .build()
                    .verify(jwe);
            }
        }

    }
}
