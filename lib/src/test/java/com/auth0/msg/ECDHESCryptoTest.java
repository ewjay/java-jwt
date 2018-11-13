package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.ConcatKDF;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Map;

public class ECDHESCryptoTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    public byte[] makeOtherInfo(byte[] algId, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(algId.length +
            partyUInfo.length +
            partyVInfo.length +
            suppPrivInfo.length +
            suppPubInfo.length
        ).put(algId).put(partyUInfo).put(partyVInfo).put(suppPrivInfo).put(suppPubInfo);
        return byteBuffer.array();
    }

    public byte[] makeOtherInfo(String algId, String partyUInfo, String partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo) {
        int bufferSize = 0;
        if(algId != null) {
            bufferSize += algId.length() + 4;
        }
        if(partyUInfo != null) {
            bufferSize += partyUInfo.length() + 4;
        }
        if (partyVInfo != null) {
            bufferSize += partyVInfo.length() + 4;
        }
        if(suppPubInfo != null) {
            bufferSize += suppPubInfo.length;
        }
        if(suppPrivInfo != null) {
            bufferSize += suppPrivInfo.length;
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(bufferSize);
        IntBuffer intBuffer = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).asIntBuffer();
        if(algId != null) {
            byteBuffer.putInt(algId.length()).put(algId.getBytes(StandardCharsets.US_ASCII));
        }
        if(partyUInfo != null) {
            byteBuffer.putInt(partyUInfo.length()).put(partyUInfo.getBytes(StandardCharsets.US_ASCII));
        }
        if (partyVInfo != null) {
            byteBuffer.putInt(partyVInfo.length()).put(partyVInfo.getBytes(StandardCharsets.US_ASCII));
        }
        if(suppPubInfo != null) {
            byteBuffer.put(suppPubInfo);
        }
        if(suppPrivInfo != null) {
            byteBuffer.put(suppPrivInfo);
        }

        System.out.println("Byte Bufer = " + Hex.encodeHexString(byteBuffer.array()));
        return byteBuffer.array();
    }

    public int computeDigestCycles(final int digestLengthBits, final int keyLengthBits) {

        // return the ceiling of keyLength / digestLength
        System.out.printf("key + digest -1 = %d\n", keyLengthBits + digestLengthBits - 1);

        return (keyLengthBits + digestLengthBits - 1) / digestLengthBits;
    }

    byte[] concatKDF(String hashAlg, int keyDataLen, byte[] Z, byte[] otherInfo) throws Exception{
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        if(hashAlg != null) {
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlg);
            int repetitions = (messageDigest.getDigestLength() + keyDataLen - 1) / messageDigest.getDigestLength();
            ByteBuffer byteBuffer = ByteBuffer.allocate(4 + Z.length + otherInfo.length);
            byteBuffer.putInt(0).put(Z).put(otherInfo);
            for(int i = 1; i <= repetitions; i++) {
                byteBuffer.putInt(0, i);
                System.out.printf("Round %d = %s\n", i, Hex.encodeHexString(byteBuffer.array()));
                messageDigest.update(byteBuffer.array());
                byteArrayOutputStream.write(messageDigest.digest());
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

/*
    @Test
    public void testECDH_ES_KeyAgreement() throws Exception {
        ECKey senderKey = ECKey.privateKeyBuilder("P-256",
            "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo").build();

        ECKey receiverKey = ECKey.privateKeyBuilder("P-256",
            "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw").build();

        Algorithm ecdh = Algorithm.ECDH_ES((ECPrivateKey) senderKey.getKey(true), (ECPublicKey) receiverKey.getKey(false));
        byte[] sharedKey = ecdh.generateAgreementKey();
        System.out.println("Shared secret = " + Hex.encodeHexString(sharedKey));

        short[] expected = new short[]{
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
            38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
            140, 254, 144, 196
        };

        ByteBuffer expectedBytes = ByteBuffer.allocate(expected.length);

        for(short num : expected) {
            expectedBytes.put((byte) num);
        }

        Assert.assertTrue(Arrays.equals(expectedBytes.array(), sharedKey));

        short[] expectedOther = new short[]{
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
            99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128
        };

        ByteBuffer expectedOtherBytes = ByteBuffer.allocate(expectedOther.length);

        for(short num : expectedOther) {
            expectedOtherBytes.put((byte) num);
        }

        int keyDataLen = 128;
        ByteBuffer byteBuffer = ByteBuffer.allocate(4).putInt(keyDataLen);
        ConcatKDF concatKDF = ConcatKDF.SHA256ConcatKDF();

//        byte[] otherInfo = makeOtherInfo("A128GCM", "Alice", "Bob", byteBuffer.array(), null);
        byte[] otherInfo = concatKDF.makeJWEOtherInfo("A128GCM", "Alice", "Bob", keyDataLen, null);
        System.out.println("OtherInfo = " + Hex.encodeHexString(otherInfo));


        Assert.assertTrue(Arrays.equals(expectedOtherBytes.array(), otherInfo));


//        byte[] sharedSecret = concatKDF("SHA-256", 16, sharedKey, otherInfo);
        byte[] sharedSecret = concatKDF.getKDFSecret(16, sharedKey, otherInfo);
        System.out.println("concatKDF = " + Hex.encodeHexString(sharedSecret));

        short[] expectedSecret = new short[] {
            86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
        };

        ByteBuffer expectedSecretBytes = ByteBuffer.allocate(expectedSecret.length);

        for(short num : expectedSecret) {
            expectedSecretBytes.put((byte) num);
        }

        System.out.println("expectedSecret = " + Hex.encodeHexString(expectedSecretBytes.array()));
        System.out.println("sharedSecret = " + Hex.encodeHexString(Arrays.copyOfRange(sharedSecret, 0, 16)));

        Assert.assertTrue(Arrays.equals(Arrays.copyOfRange(sharedSecret, 0, 16), expectedSecretBytes.array()));



//        ByteBuffer byteBuffer = ByteBuffer.allocate(expected.length * (Short.SIZE / Byte.SIZE));
//        ShortBuffer shortBuffer = byteBuffer.asShortBuffer().put(expected);
//
//        System.out.println(Hex.encodeHexString(byteBuffer.array()));
//
//        System.out.println(Hex.encodeHexString(shortBytes.array()));
    }
*/

    @Test
    public void testECDH_ES_KeyAgreementKDF() throws Exception {
        ECKey senderKey = ECKey.privateKeyBuilder("P-256",
            "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo").build();

        ECKey receiverKey = ECKey.privateKeyBuilder("P-256",
            "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw").build();

        Algorithm ecdh = Algorithm.ECDH_ES((ECPrivateKey) senderKey.getKey(true), (ECPublicKey) senderKey.getKey(false), (ECPublicKey) receiverKey.getKey(false), "Alice", "Bob", "A128GCM", 16);

        byte[] agreementKey = ecdh.generateAgreementKey();
        System.out.println("Agreement key = " + Hex.encodeHexString(agreementKey));
        short[] expectedAgreementKeyShorts = new short[]{
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
            38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
            140, 254, 144, 196
        };
        byte[] expectedAgreementKey = TestUtils.convertShortArrayToByteArray(expectedAgreementKeyShorts);
        Assert.assertTrue(Arrays.equals(expectedAgreementKey, agreementKey));

        int keyDataLen = 128;
        ByteBuffer byteBuffer = ByteBuffer.allocate(4).putInt(keyDataLen);
        ConcatKDF concatKDF = ConcatKDF.SHA256ConcatKDF();
        byte[] otherInfo = concatKDF.makeJWEOtherInfo("A128GCM", "Alice", "Bob", keyDataLen, null);
        System.out.println("OtherInfo = " + Hex.encodeHexString(otherInfo));
        short[] expectedOtherInfoShorts = new short[]{
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
            99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128
        };
        byte[] expectedOtherInfo = TestUtils.convertShortArrayToByteArray(expectedOtherInfoShorts);
        Assert.assertTrue(Arrays.equals(expectedOtherInfo, otherInfo));

        byte[] derivedSecret = concatKDF.getKDFSecret(16, agreementKey, otherInfo);
        byte[] derivedSecret2 = ecdh.generateDerivedKey();
        System.out.println("concatKDF = " + Hex.encodeHexString(derivedSecret));
        short[] expectedDerivedSecretShorts = new short[] {
            86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
        };
        byte[] expectedSecret = TestUtils.convertShortArrayToByteArray(expectedDerivedSecretShorts);

        System.out.println("expected Derived Key = " + Hex.encodeHexString(expectedSecret));
        System.out.println("Derived Key = " + Hex.encodeHexString(derivedSecret));

        Assert.assertTrue(Arrays.equals(derivedSecret, expectedSecret));
        Assert.assertTrue(Arrays.equals(derivedSecret2, expectedSecret));
    }


    @Test
    public void testECDH_ES_KeyAgreement() throws Exception {
        ECKey senderKey = ECKey.privateKeyBuilder("P-256",
            "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo").build();

        ECKey receiverKey = ECKey.privateKeyBuilder("P-256",
            "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw").build();

        Algorithm ecdh = Algorithm.ECDH_ES((ECPrivateKey) senderKey.getKey(true), (ECPublicKey) senderKey.getKey(false), (ECPublicKey) receiverKey.getKey(false), "Alice", "Bob", "A128GCM", 16);
        byte[] derivedKey = ecdh.generateDerivedKey();
        System.out.println("Derived key = " + Hex.encodeHexString(derivedKey));
        short[] expectedDerivedKeyShorts = new short[] {
            86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
        };
        byte[] expectedDerivedKey = TestUtils.convertShortArrayToByteArray(expectedDerivedKeyShorts);
        System.out.println("Expected Derived key = " + Hex.encodeHexString(expectedDerivedKey));
        Assert.assertTrue(Arrays.equals(derivedKey, expectedDerivedKey));


        Algorithm ecdhReceiver = Algorithm.ECDH_ES((ECPrivateKey) receiverKey.getKey(true), (ECPublicKey) receiverKey.getKey(false), (ECPublicKey) senderKey.getKey(false), "Alice", "Bob", "A128GCM", 16);
        byte[] receiverDerivedKey = ecdhReceiver.generateDerivedKey();
        Assert.assertTrue(Arrays.equals(receiverDerivedKey, expectedDerivedKey));
    }

    @Test
    public void testECDH_ES_KeyWrap() throws Exception {
        ECKey senderKey = ECKey.privateKeyBuilder("P-256",
            "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo").build();

        ECKey receiverKey = ECKey.privateKeyBuilder("P-256",
            "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw").build();

        Algorithm ecdhSender = Algorithm.ECDH_ES_A128KW((ECPrivateKey) senderKey.getKey(true), (ECPublicKey) senderKey.getKey(false), (ECPublicKey) receiverKey.getKey(false), "Alice", "Bob", "A128GCM", 16);
        SecureRandom secureRandom = new SecureRandom();
        byte[] cek = new byte[16];
        secureRandom.nextBytes(cek);
        System.out.println("CEK = " + Hex.encodeHexString(cek));

        byte[] wrappedCek = ecdhSender.wrap(cek);
        System.out.println("Wrapped CEK = " + Hex.encodeHexString(wrappedCek));

        Algorithm ecdhReceiver = Algorithm.ECDH_ES_A128KW((ECPrivateKey) receiverKey.getKey(true), (ECPublicKey) receiverKey.getKey(false), (ECPublicKey) senderKey.getKey(false), "Alice", "Bob", "A128GCM", 16);

        byte[] unwrappedCek = ecdhReceiver.unwrap(wrappedCek);
        System.out.println("Unwrapped CEK = " + Hex.encodeHexString(unwrappedCek));

        Assert.assertTrue(Arrays.equals(cek, unwrappedCek));


    }

    @Test
    public void testECDH_ESDHES_JWE() throws Exception {
//        ECKey senderKey = ECKey.privateKeyBuilder("P-256",
//            "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//            "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
//            "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo").build();
//
//        ECKey receiverKey = ECKey.privateKeyBuilder("P-256",
//            "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
//            "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
//            "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw").build();
//
//
//        KeyPair senderKeyPair = ECKey.generateECKeyPair("P-256");
//        if(senderKeyPair != null) {
//            ECKey sederPubKey = ECKey.keyBuilder(senderKeyPair.getPublic()).build();
//            System.out.println(sederPubKey.toDict().toString());
//        }
//        KeyPair receiverKeyPair = ECKey.generateECKeyPair("P-256");
//        if(receiverKeyPair != null) {
//            ECKey receiverPubKey = ECKey.keyBuilder(receiverKeyPair.getPublic()).build();
//            System.out.println(receiverPubKey.toDict().toString());
//        }
//
//        Algorithm senderAlg = Algorithm.ECDH_ES((ECPrivateKey) senderKeyPair.getPrivate(), (ECPublicKey) senderKeyPair.getPublic(), (ECPublicKey)receiverKeyPair.getPublic(), "Alice", "Tom", "A128CBC-HS256", 256);
//        CipherParams cipherParams = CipherParams.getKeyAgreementInstance("A128CBC-HS256", senderAlg);
//        Algorithm senderEnc = Algorithm.A128CBC_HS256(cipherParams);
//
//
//        JWTCreator.Builder builder = JWT.create()
//            .withClaim("gender", "F")
//            .withAudience("Bob")
//            .withIssuer("Mark")
//            .withSubject("Alice")
//            .withClaim("birthdate", "20180101");
//        String jwe = builder.encrypt(senderAlg, senderEnc);
//        System.out.println(jwe);
//
//        Algorithm receiverAlg = Algorithm.ECDH_ES((ECPrivateKey) receiverKeyPair.getPrivate(), (ECPublicKey) receiverKeyPair.getPublic(), (ECPublicKey)senderKeyPair.getPublic(), "Alice", "Tom", "A128CBC-HS256", 256);
//
//
//        DecodedJWT jwt = JWT.require(receiverAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
//            .build()
//            .verify(jwe);


        String[] ecCurves = new String[] {"P-256", "P-384", "P-521"};
        String[] encs = new String[] {"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"};
        for(String ecCurve : ecCurves) {
            for(String enc : encs) {
                System.out.printf("%s %s\n==========\n", ecCurve, enc);

                KeyPair senderKeyPair = ECKey.generateECKeyPair(ecCurve);
                if(senderKeyPair != null) {
                    ECKey sederPubKey = ECKey.keyBuilder(senderKeyPair.getPublic()).build();
                    System.out.println(sederPubKey.toDict().toString());
                }
                KeyPair receiverKeyPair = ECKey.generateECKeyPair(ecCurve);
                if(receiverKeyPair != null) {
                    ECKey receiverPubKey = ECKey.keyBuilder(receiverKeyPair.getPublic()).build();
                    System.out.println(receiverPubKey.toDict().toString());
                }
                int keydatalen = Algorithm.getAlgorithmKeydataLen(enc);
                Algorithm senderAlg = Algorithm.ECDH_ES((ECPrivateKey) senderKeyPair.getPrivate(), (ECPublicKey) senderKeyPair.getPublic(), (ECPublicKey)receiverKeyPair.getPublic(), "Alice", "Tom", enc, keydatalen);
                CipherParams cipherParams = CipherParams.getKeyAgreementInstance(enc, senderAlg);
                Algorithm senderEnc = Algorithm.getContentEncryptionAlg(enc, cipherParams);

                JWTCreator.Builder builder = JWT.create()
                    .withClaim("gender", "F")
                    .withAudience("Bob")
                    .withIssuer("Mark")
                    .withSubject("Alice")
                    .withClaim("birthdate", "20180101");
                String jwe = builder.encrypt(senderAlg, senderEnc);
                System.out.println(jwe);

                DecodedJWT decodedJWT = JWT.decode(jwe);

                String apu = decodedJWT.getHeaderClaim("apu").asString();
                String apv = decodedJWT.getHeaderClaim("apv").asString();
                Map<String, Object> epk = decodedJWT.getHeaderClaim("epk").asMap();



//                Algorithm receiverAlg = Algorithm.ECDH_ES((ECPrivateKey) receiverKeyPair.getPrivate(), (ECPublicKey) receiverKeyPair.getPublic(), (ECPublicKey)senderKeyPair.getPublic(), "Alice", "Tom", enc, keydatalen);
                ECKey ephermeralKey = ECKey.publicKeyBuilder((String) epk.get("crv"), (String) epk.get("x"), (String) epk.get("y")).build();
                Algorithm receiverAlg = Algorithm.ECDH_ES((ECPrivateKey) receiverKeyPair.getPrivate(), null, (ECPublicKey)ephermeralKey.getKey(false), apu, apv, enc, keydatalen);

                DecodedJWT jwt = JWT.require(receiverAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
                    .build()
                    .verify(jwe);
            }
        }

    }


    @Test
    public void testECDH_ESDHES_JWE2() throws Exception {
        String[] ecCurves = new String[] {"P-256", "P-384", "P-521"};
        String[] encs = new String[] {"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"};
        for(String ecCurve : ecCurves) {
            for(String enc : encs) {
                System.out.printf("%s %s\n==========\n", ecCurve, enc);

                KeyPair senderKeyPair = ECKey.generateECKeyPair(ecCurve);
                if(senderKeyPair != null) {
                    ECKey sederPubKey = ECKey.keyBuilder(senderKeyPair.getPublic()).build();
                    System.out.println(sederPubKey.toDict().toString());
                }
                KeyPair receiverKeyPair = ECKey.generateECKeyPair(ecCurve);
                if(receiverKeyPair != null) {
                    ECKey receiverPubKey = ECKey.keyBuilder(receiverKeyPair.getPublic()).build();
                    System.out.println(receiverPubKey.toDict().toString());
                }
//                int keydatalen = Algorithm.getAlgorithmKeydataLen(enc);
                Algorithm senderAlg = Algorithm.ECDH_ES((ECPrivateKey) senderKeyPair.getPrivate(), (ECPublicKey) senderKeyPair.getPublic(), (ECPublicKey)receiverKeyPair.getPublic(), "Alice", "Tom", enc);
                CipherParams cipherParams = CipherParams.getKeyAgreementInstance(enc, senderAlg);
                Algorithm senderEnc = Algorithm.getContentEncryptionAlg(enc, cipherParams);

                JWTCreator.Builder builder = JWT.create()
                    .withClaim("gender", "F")
                    .withAudience("Bob")
                    .withIssuer("Mark")
                    .withSubject("Alice")
                    .withClaim("birthdate", "20180101");
                String jwe = builder.encrypt(senderAlg, senderEnc);
                System.out.println(jwe);

                DecodedJWT decodedJWT = JWT.decode(jwe);

                String apu = decodedJWT.getHeaderClaim("apu").asString();
                String apv = decodedJWT.getHeaderClaim("apv").asString();
                Map<String, Object> epk = decodedJWT.getHeaderClaim("epk").asMap();
//                Algorithm receiverAlg = Algorithm.ECDH_ES((ECPrivateKey) receiverKeyPair.getPrivate(), (ECPublicKey) receiverKeyPair.getPublic(), (ECPublicKey)senderKeyPair.getPublic(), "Alice", "Tom", enc, keydatalen);
                ECKey ephermeralKey = ECKey.publicKeyBuilder((String) epk.get("crv"), (String) epk.get("x"), (String) epk.get("y")).build();
                Algorithm receiverAlg = Algorithm.ECDH_ES((ECPrivateKey) receiverKeyPair.getPrivate(), null, (ECPublicKey)ephermeralKey.getKey(false), apu, apv, enc);

                DecodedJWT jwt = JWT.require(receiverAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
                    .build()
                    .verify(jwe);
            }
        }

    }

    @Test
    public void testECDH_ECDHES_KeyWrap() throws Exception {
        KeyPair senderKeyPair = ECKey.generateECKeyPair("P-256");
        if(senderKeyPair != null) {
            ECKey sederPubKey = ECKey.keyBuilder(senderKeyPair.getPublic()).build();
            System.out.println(sederPubKey.toDict().toString());
        }
        KeyPair receiverKeyPair = ECKey.generateECKeyPair("P-256");
        if(receiverKeyPair != null) {
            ECKey receiverPubKey = ECKey.keyBuilder(receiverKeyPair.getPublic()).build();
            System.out.println(receiverPubKey.toDict().toString());
        }

        Algorithm senderAlg = Algorithm.ECDH_ES_A128KW((ECPrivateKey) senderKeyPair.getPrivate(), (ECPublicKey) senderKeyPair.getPublic(), (ECPublicKey)receiverKeyPair.getPublic(), "Alice", "Tom", "ECDH-ES+A128KW", 128);
        CipherParams cipherParams = CipherParams.getInstance("A128CBC-HS256");
        Algorithm senderEnc = Algorithm.A128CBC_HS256(cipherParams);


        JWTCreator.Builder builder = JWT.create()
            .withClaim("gender", "F")
            .withAudience("Bob")
            .withIssuer("Mark")
            .withSubject("Alice")
            .withClaim("birthdate", "20180101");
        String jwe = builder.encrypt(senderAlg, senderEnc);
        System.out.println(jwe);

        Algorithm receiverAlg = Algorithm.ECDH_ES_A128KW((ECPrivateKey) receiverKeyPair.getPrivate(), (ECPublicKey) null, (ECPublicKey)senderKeyPair.getPublic(), "Alice", "Tom", "ECDH-ES+A128KW", 128);


        DecodedJWT jwt = JWT.require(receiverAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
            .build()
            .verify(jwe);
    }

    @Test
    public void testECDH_ECDHES_KeyWrap2() throws Exception {
        String[] ecCurves = new String[] {"P-256", "P-384", "P-521"};
        String[] kwAlgs = new String[] {"ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"};
        String[] encs = new String[] {"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"};
        for(String ecCurve : ecCurves) {
            for(String kwAlg : kwAlgs) {
                for(String enc : encs) {
                    System.out.printf("%s %s %s\n==========\n", ecCurve, kwAlg, enc);

                    KeyPair senderKeyPair = ECKey.generateECKeyPair(ecCurve);
                    if(senderKeyPair != null) {
                        ECKey sederPubKey = ECKey.keyBuilder(senderKeyPair.getPublic()).build();
                        System.out.println(sederPubKey.toDict().toString());
                    }
                    KeyPair receiverKeyPair = ECKey.generateECKeyPair(ecCurve);
                    if(receiverKeyPair != null) {
                        ECKey receiverPubKey = ECKey.keyBuilder(receiverKeyPair.getPublic()).build();
                        System.out.println(receiverPubKey.toDict().toString());
                    }
                    int keydatalen = Algorithm.getAlgorithmKeydataLen(kwAlg);

                    Algorithm senderAlg = Algorithm.getECDHES_KeyWrapAlg(kwAlg, (ECPrivateKey) senderKeyPair.getPrivate(), (ECPublicKey) senderKeyPair.getPublic(), (ECPublicKey)receiverKeyPair.getPublic(), "Alice", "Tom", kwAlg, keydatalen);
                    CipherParams cipherParams = CipherParams.getInstance(enc);
                    Algorithm senderEnc = Algorithm.getContentEncryptionAlg(enc, cipherParams);

                    JWTCreator.Builder builder = JWT.create()
                        .withClaim("gender", "F")
                        .withAudience("Bob")
                        .withIssuer("Mark")
                        .withSubject("Alice")
                        .withClaim("birthdate", "20180101");
                    String jwe = builder.encrypt(senderAlg, senderEnc);
                    System.out.println(jwe);

                    DecodedJWT decodedJWT = JWT.decode(jwe);

                    String apu = decodedJWT.getHeaderClaim("apu").asString();
                    String apv = decodedJWT.getHeaderClaim("apv").asString();
                    Map<String, Object> epk = decodedJWT.getHeaderClaim("epk").asMap();
                    ECKey ephermeralKey = ECKey.publicKeyBuilder((String) epk.get("crv"), (String) epk.get("x"), (String) epk.get("y")).build();
                    Algorithm receiverAlg = Algorithm.getECDHES_KeyWrapAlg(kwAlg, (ECPrivateKey) receiverKeyPair.getPrivate(), null, (ECPublicKey)ephermeralKey.getKey(false), apu, apv, kwAlg, keydatalen);

                    DecodedJWT jwt = JWT.require(receiverAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
                        .build()
                        .verify(jwe);
                }

            }
        }

    }

    @Test
    public void testECDH_ECDHES_KeyWrap3() throws Exception {
        String[] ecCurves = new String[] {"P-256", "P-384", "P-521"};
        String[] kwAlgs = new String[] {"ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"};
        String[] encs = new String[] {"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"};
        for(String ecCurve : ecCurves) {
            for(String kwAlg : kwAlgs) {
                for(String enc : encs) {
                    System.out.printf("%s %s %s\n==========\n", ecCurve, kwAlg, enc);

                    KeyPair senderKeyPair = ECKey.generateECKeyPair(ecCurve);
                    if(senderKeyPair != null) {
                        ECKey sederPubKey = ECKey.keyBuilder(senderKeyPair.getPublic()).build();
                        System.out.println(sederPubKey.toDict().toString());
                    }
                    KeyPair receiverKeyPair = ECKey.generateECKeyPair(ecCurve);
                    if(receiverKeyPair != null) {
                        ECKey receiverPubKey = ECKey.keyBuilder(receiverKeyPair.getPublic()).build();
                        System.out.println(receiverPubKey.toDict().toString());
                    }
                    Algorithm senderAlg = Algorithm.getECDHES_KeyWrapAlg(kwAlg, (ECPrivateKey) senderKeyPair.getPrivate(), (ECPublicKey) senderKeyPair.getPublic(), (ECPublicKey)receiverKeyPair.getPublic(), "Alice", "Tom", kwAlg);
                    CipherParams cipherParams = CipherParams.getInstance(enc);
                    Algorithm senderEnc = Algorithm.getContentEncryptionAlg(enc, cipherParams);

                    JWTCreator.Builder builder = JWT.create()
                        .withClaim("gender", "F")
                        .withAudience("Bob")
                        .withIssuer("Mark")
                        .withSubject("Alice")
                        .withClaim("birthdate", "20180101");
                    String jwe = builder.encrypt(senderAlg, senderEnc);
                    System.out.println(jwe);

                    DecodedJWT decodedJWT = JWT.decode(jwe);

                    String apu = decodedJWT.getHeaderClaim("apu").asString();
                    String apv = decodedJWT.getHeaderClaim("apv").asString();
                    Map<String, Object> epk = decodedJWT.getHeaderClaim("epk").asMap();
                    ECKey ephermeralKey = ECKey.publicKeyBuilder((String) epk.get("crv"), (String) epk.get("x"), (String) epk.get("y")).build();
                    Algorithm receiverAlg = Algorithm.getECDHES_KeyWrapAlg(kwAlg, (ECPrivateKey) receiverKeyPair.getPrivate(), null, (ECPublicKey)ephermeralKey.getKey(false), apu, apv, kwAlg);

                    DecodedJWT jwt = JWT.require(receiverAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
                        .build()
                        .verify(jwe);
                }

            }
        }

    }

    @Test
    public void testECDH_KeyWrap() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] kek = new byte[24];
        secureRandom.nextBytes(kek);
        Algorithm senderAlg = Algorithm.AES192Keywrap(kek);
        CipherParams cipherParams = CipherParams.getInstance("A128CBC-HS256");
        Algorithm senderEnc = Algorithm.A128CBC_HS256(cipherParams);


        JWTCreator.Builder builder = JWT.create()
            .withClaim("gender", "F")
            .withAudience("Bob")
            .withIssuer("Mark")
            .withSubject("Alice")
            .withClaim("birthdate", "20180101");
        String jwe = builder.encrypt(senderAlg, senderEnc);
        System.out.println(jwe);



        DecodedJWT jwt = JWT.require(senderAlg).withIssuer("Mark").withAudience("Bob").withSubject("Alice").withClaim("gender", "F")
            .build()
            .verify(jwe);
    }

}
