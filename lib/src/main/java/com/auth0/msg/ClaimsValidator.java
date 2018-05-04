package com.auth0.msg;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.impl.PublicClaims;

import java.lang.reflect.Array;
import java.util.*;

public final class ClaimsValidator {
    private final static Map<String, Claim> knownClaims = new HashMap<>();

    static {
        knownClaims.put("alg", new Claim("alg", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.STRING));
        knownClaims.put("cty", new Claim("cty", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.STRING));
        knownClaims.put("typ", new Claim("typ", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.STRING));
        knownClaims.put("kid", new Claim("kid", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.STRING));
        knownClaims.put("iss", new Claim("iss", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.STRING));
        knownClaims.put("sub", new Claim("sub", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.STRING));
        knownClaims.put("exp", new Claim("exp", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.DATE));
        knownClaims.put("nbf", new Claim("kid", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.DATE));
        knownClaims.put("iat", new Claim("kid", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.DATE));
    }

    public static boolean isKnownClaim (String name){
        return knownClaims.containsKey(name);
    }

    public static boolean validate(String claimName, Object value, MessageType type){
        Claim targetClaim = knownClaims.get(claimName);
        switch (targetClaim.getType()) {
            case BOOLEAN:
                if (!(value instanceof Boolean)) {
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
            case STRING:
                if (!(value instanceof String)) {
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
            case INT:
                if (!(value instanceof Integer)) {  // The value object cannot be a primitive
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
            case LIST:
                if (!(value instanceof List)) {
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
            case ARRAY:
                if (!(value instanceof Array)) {
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
            case DATE:
                if (!(value instanceof Date)) {
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
            case LONG:
                if (!(value instanceof Long)) {
                    throw new InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim", claimName));
                }
        }
        Map<MessageType, List<Object>> allowedMessageTypes = targetClaim.getAllowedValues();
        List<Object> allowedValues = allowedMessageTypes.get(type);
        if (!allowedValues.contains(value)) {
            throw new InvalidClaimException(String.format("The claim '%s' value is not allowed for this claim type", claimName));
        }
        return true;
    }
}
