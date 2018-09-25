package com.auth0.jwt.exceptions;

public class KDFException extends Exception {
    public KDFException(String msg) {
        super("KDF error : " + msg);
    }

    public KDFException(String msg, Throwable e) {
        super("KDF error : " + msg, e);
    }
}
