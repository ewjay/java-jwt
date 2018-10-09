package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.KDFException;
import com.auth0.msg.TestUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ConcatKDFTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void shouldFailWithNullAlg() throws Exception {
        exception.expect(KDFException.class);
        exception.expectMessage("Hash algorithm cannot be null");
        ConcatKDF concatKDF = new ConcatKDF(null);
    }

    @Test
    public void testMakeOtherInfo() throws Exception {
        short[] zShorts = new short[] {
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
            38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
            140, 254, 144, 196
        };
        byte[] Z = TestUtils.convertShortArrayToByteArray(zShorts);
        byte[] keydatalen = ByteBuffer.allocate(4).putInt(128).array();
        byte[] algId = ByteBuffer.allocate(11).putInt(7).put("A128GCM".getBytes(StandardCharsets.US_ASCII)).array();
        byte[] partyU = ByteBuffer.allocate(9).putInt(5).put("Alice".getBytes(StandardCharsets.US_ASCII)).array();
        byte[] partyV = ByteBuffer.allocate(7).putInt(3).put("Bob".getBytes(StandardCharsets.US_ASCII)).array();
        byte[] suppPubInfo = ByteBuffer.allocate(4).putInt(128).array();
        byte[] suppPrivInfo = new byte[0];

        short[] resultShorts = new short[] {
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
            99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128
        };
        byte[] expectedResult = TestUtils.convertShortArrayToByteArray(resultShorts);

        ConcatKDF concatKDF = ConcatKDF.SHA256ConcatKDF();
        byte[] result = concatKDF.makeOtherInfo(algId, partyU, partyV, suppPubInfo, suppPrivInfo);
        Assert.assertTrue(Arrays.equals(expectedResult, result));
    }

    @Test
    public void testMakeJWEOtherInfo() throws Exception {
        short[] resultShorts = new short[] {
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
            99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128
        };
        byte[] expectedResult = TestUtils.convertShortArrayToByteArray(resultShorts);

        ConcatKDF concatKDF = ConcatKDF.SHA256ConcatKDF();
        byte[] result = concatKDF.makeJWEOtherInfo("A128GCM", "Alice", "Bob", 128, null);
        Assert.assertTrue(Arrays.equals(expectedResult, result));
    }

    @Test
    public void testConcatKDF() throws Exception {
        short[] zShorts = new short[] {
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
            38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
            140, 254, 144, 196
        };
        byte[] Z = TestUtils.convertShortArrayToByteArray(zShorts);
        byte[] keydatalen = ByteBuffer.allocate(4).putInt(128).array();
        byte[] algId = ByteBuffer.allocate(11).putInt(7).put("A128GCM".getBytes(StandardCharsets.US_ASCII)).array();
        byte[] partyU = ByteBuffer.allocate(9).putInt(5).put("Alice".getBytes(StandardCharsets.US_ASCII)).array();
        byte[] partyV = ByteBuffer.allocate(7).putInt(3).put("Bob".getBytes(StandardCharsets.US_ASCII)).array();
        byte[] suppPubInfo = ByteBuffer.allocate(4).putInt(128).array();
        byte[] suppPrivInfo = new byte[0];

        short[] expectedOtherInfoShorts = new short[] {
            0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
            99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128
        };
        byte[] expectedOtherInfoResult = TestUtils.convertShortArrayToByteArray(expectedOtherInfoShorts);

        ConcatKDF concatKDF = ConcatKDF.SHA256ConcatKDF();
        byte[] otherInfoResult = concatKDF.makeOtherInfo(algId, partyU, partyV, suppPubInfo, suppPrivInfo);
        Assert.assertTrue(Arrays.equals(expectedOtherInfoResult, otherInfoResult));

        short[] expectedDerivedKeyShorts = new short[] {
            86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16,
            26
        };
        byte[] expectedDerivedKey = TestUtils.convertShortArrayToByteArray(expectedDerivedKeyShorts);
        byte[] derivedKeyResult = concatKDF.getKDFSecret(16, Z, otherInfoResult);
        Assert.assertTrue(Arrays.equals(expectedDerivedKey, derivedKeyResult));
    }


}
