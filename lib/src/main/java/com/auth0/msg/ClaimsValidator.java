package com.auth0.msg;

import static com.auth0.msg.ClaimType.STRING;
import static com.auth0.msg.MessageType.*;


import java.lang.reflect.Array;
import java.util.*;


public final class ClaimsValidator {
    private final static Map<String, Claim> knownClaims = new HashMap<>();

    static {
        knownClaims.put("alg", new Claim("alg", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("cty", new Claim("cty", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("typ", new Claim("typ", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("kid", new Claim("kid", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("iss", new Claim("iss", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("sub", new Claim("sub", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("aud", new Claim("aud", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("exp", new Claim("exp", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.DATE));
        knownClaims.put("nbf", new Claim("kid", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.DATE));
        knownClaims.put("iat", new Claim("kid", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.DATE));
        knownClaims.put("scope", new Claim("scope", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("refresh_token", new Claim("refresh_token", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("code", new Claim("code", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("response_type", new Claim("response_type", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("client_id", new Claim("client_id", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("access_token", new Claim("access_token", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("token_type", new Claim("token_type", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("response_types_supported", new Claim("sub", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("grant_types_supported", new Claim("sub", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("response_type", new Claim("response_type", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("redirect_uri", new Claim("redirect_uri", Collections.<MessageType, List<Object>>emptyMap(), STRING));
        knownClaims.put("redirect_uris", new Claim("redirect_uri", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.LIST));
        knownClaims.put("id_token", new Claim("id_token", Collections.<MessageType, List<Object>>emptyMap(), ClaimType.ID_TOKEN));

        Map<MessageType, List<Object>> grant_type_values = new HashMap<>();
        grant_type_values.put(REFRESH_ACCESS_TOKEN_REQUEST, Arrays.asList((Object)"refresh_token"));
        grant_type_values.put(CC_ACCESS_TOKEN_REQUEST, Arrays.asList((Object)"client_credentials"));
        knownClaims.put("grant_type", new Claim("grant_type", grant_type_values, STRING));

        //TODO Add all known claims
    }

    public static boolean isKnownClaim (String name){
        return knownClaims.containsKey(name);
    }

    public static void validate(String claimName, Object value, MessageType msgType) throws InvalidClaimException {

        // TODO validate and update the value to the correct type - the value that we get from developer can be
        // transformed into the allowed type and if that's the case then we should update the value to the correct allowed type
        // for example: developer can provide epoch as a number or as a string representation of a number. This validation should
        // allow for both of these but at the end update the value with the number representation of the epoch. Another example
        // is for a list of string developer may only provide one string. Our validate should allow that value but at the end update
        // the value to a list of one string
        Claim targetClaim = knownClaims.get(claimName);
        switch (targetClaim.getType()) {
            case ID_TOKEN:
                ((IDToken) value).verify();
            case BOOLEAN:
                if (!(value instanceof Boolean)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
            case STRING:
                if (!(value instanceof String)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
            case INT:
                if (!(value instanceof Integer)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
            case LIST:
                if (!(value instanceof List) || (((List) value).get(0) instanceof String)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
            case ARRAY:
                if (!(value instanceof Array)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
            case DATE:
                if (!(value instanceof Date)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
            case LONG:
                if (!(value instanceof Long)) {
                    throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' type is not appropriate for this claim'", claimName));
                }
                break;
        }
        Map<MessageType, List<Object>> allowedMessageTypes = targetClaim.getAllowedValues();
        List<Object> allowedValues = allowedMessageTypes.get(msgType);

        if (allowedValues !=null) {
            if (targetClaim.getType() == STRING) {
                value = value.toString().toLowerCase();
            }
            if (!allowedValues.contains(value)) {
                throw new com.auth0.jwt.exceptions.InvalidClaimException(String.format("The claim '%s' value is not allowed for this claim type", claimName));
            }
        }
    }
}
