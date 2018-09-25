package com.auth0.msg;

import java.nio.ByteBuffer;

public abstract class TestUtils {

    public static byte[] convertShortArrayToByteArray(short[] shorts) {
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

}
