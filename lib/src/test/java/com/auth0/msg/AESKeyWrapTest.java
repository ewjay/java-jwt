package com.auth0.msg;

import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESKeyWrapTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    public byte[] convertShortArrayToByteArray(short[] shorts) {
        if(shorts != null) {
            ByteBuffer byteBuffer = ByteBuffer.allocate(shorts.length);
            for(short num : shorts) {
                byteBuffer.put((byte) num);
            }
            return byteBuffer.array();
        } else {
            return new byte[0];
        }
    }

    @Test
    public void testKeyWrap() throws Exception {
        byte[] kek = Base64.decodeBase64("GawgguFyGrWKav7AX4VKUg");
        System.out.printf("kek = %s\n", Hex.encodeHexString(kek));
        Algorithm keyWrap = Algorithm.AES128Keywrap(kek);

        short[] cekShorts = new short[] {
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
            206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
            44, 207
        };

        byte[] cek = convertShortArrayToByteArray(cekShorts);
        System.out.printf("cek = %s\n", Hex.encodeHexString(cek));

        short[] expectedWrappedShorts = new short[] {
            232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
            22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
            76, 124, 193, 11, 98, 37, 173, 61, 104, 57
        };
        byte[] expectedWrapped = convertShortArrayToByteArray(expectedWrappedShorts);
        System.out.printf("Expected Wrapped Key = %s\n", Hex.encodeHexString(expectedWrapped));

        byte[] wrappedKey = keyWrap.wrap(cek);
        System.out.printf("Wrapped Key = %s\n", Hex.encodeHexString(wrappedKey));

        Assert.assertTrue(Arrays.equals(wrappedKey, expectedWrapped));
        byte[] unwrappedKey = keyWrap.unwrap(wrappedKey);
        System.out.printf("Unwrapped Key = %s\n", Hex.encodeHexString(unwrappedKey));
        Assert.assertTrue(Arrays.equals(cek, unwrappedKey));
    }
}
