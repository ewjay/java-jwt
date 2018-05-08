package com.auth0.msg;

/**
 * An exception that is thrown when there is an invalid claim in a Message object type
 */
public class InvalidClaimException extends Exception {
    public InvalidClaimException(String message) {
        this(message, null);
    }

    public InvalidClaimException(String message, Throwable cause) {
        super(message, cause);
    }
}
