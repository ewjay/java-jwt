package com.auth0.jwt.algorithms;

import org.apache.commons.codec.binary.Base64;

public class AuthenticatedCipherText {
    private byte[] cipherText;
    private byte[] tag;

    AuthenticatedCipherText(byte[] cipherText, byte[] tag) {
        this.cipherText = cipherText;
        this.tag = tag;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public String getBase64urlCipherText() {
        return Base64.encodeBase64URLSafeString(cipherText);
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    public byte[] getTag() {
        return tag;
    }

    public String getBase64urlTag() {
        return Base64.encodeBase64URLSafeString(tag);
    }

    public void setTag(byte[] tag) {
        this.tag = tag;
    }
}
