package com.auth0.msg;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.math.BigInteger;

public abstract class Utils {

    /**
     * Decode a base64url encoded byte representation back to a BigInteger
     * @param base64encodeBigIntBytes
     * @return BigInteger
     */
    public static BigInteger base64urlToBigInt(final byte[] base64encodeBigIntBytes) {
        return Base64.decodeInteger(base64encodeBigIntBytes);
    }


    /**
     * Decode a base64url encoded string representation back to a BigInteger
     * @param base64encodedBigInt Base64encode BigInteger string
     * @return BigInteger
     */
    public static BigInteger base64urlToBigInt(final String base64encodedBigInt) {
        return base64urlToBigInt(StringUtils.getBytesUtf8(base64encodedBigInt));
    }


    /**
     * Base64Urlencode a BigInteger
     * @param bigInt BigInteger to be encoded
     * @return String base64urlencoded representation of the bigInt
     * @throws NullPointerException if null is passed
     */
    public static String bigIntToBase64url(final BigInteger bigInt) {
        if (bigInt == null) {
            throw new NullPointerException("encodeInteger called with null parameter");
        }
        byte[] unsigedInt = toUnsigedIntegerBytes(bigInt);
        return Base64.encodeBase64URLSafeString(unsigedInt);
    }


    /**
     * Returns a byte-array representation of a <code>BigInteger</code> without sign bit.
     *
     * @param bigInt
     *            <code>BigInteger</code> to be converted
     * @return a byte array representation of the BigInteger parameter
     */
    static byte[] toUnsigedIntegerBytes(final BigInteger bigInt) {
        // copied from Apache commons codec
        int bitlen = bigInt.bitLength();
        // round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bigInt.bitLength() % 8) == 0) {
            startSrc = 1;
            len--;
        }
        final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[bitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

    /**
     * Checks whether a string is null or empty
     * @param s string to check
     * @return boolean whether string is null or empty
     */
    static boolean isNullOrEmpty(final String s) {
        return s == null || s.length() == 0;
    }


}
