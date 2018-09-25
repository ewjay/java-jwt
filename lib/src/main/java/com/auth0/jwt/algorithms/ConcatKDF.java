package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.KDFException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ConcatKDF {
    final String hashAlg;

    ConcatKDF(String hashAlg) throws KDFException {
        if(hashAlg == null) {
            throw new KDFException("Invalid hash algorithm.");
        }
        this.hashAlg = hashAlg;
    }

    public static ConcatKDF SHA256ConcatKDF() throws KDFException {
        return new ConcatKDF("SHA-256");
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

    public byte[] makeJWEOtherInfo(String algId, String partyUInfo, String partyVInfo, int suppPubInfo, byte[] suppPrivInfo) {
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
        bufferSize += 4; // for suppPubInfo

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
        byteBuffer.putInt(suppPubInfo);
        if(suppPrivInfo != null) {
            byteBuffer.put(suppPrivInfo);
        }

        System.out.println("Byte Bufer = " + Hex.encodeHexString(byteBuffer.array()));
        return byteBuffer.array();
    }

    public  byte[] getKDFSecret(int keyDataLen, byte[] Z, byte[] otherInfo) throws KDFException {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlg);
            // calculate ceiling(m/n) = (m + n -1) /n
            int repetitions = (keyDataLen + messageDigest.getDigestLength() - 1) / messageDigest.getDigestLength();
            ByteBuffer byteBuffer = ByteBuffer.allocate(4 + Z.length + otherInfo.length);
            byteBuffer.putInt(0).put(Z).put(otherInfo);
            for (int i = 1; i <= repetitions; i++) {
                byteBuffer.putInt(0, i);
                System.out.printf("Round %d = %s\n", i, Hex.encodeHexString(byteBuffer.array()));
                messageDigest.update(byteBuffer.array());
                byteArrayOutputStream.write(messageDigest.digest());
            }
            return Arrays.copyOfRange(byteArrayOutputStream.toByteArray(), 0, keyDataLen);
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new KDFException("ConcatKDF error", e);
        }
    }

}
