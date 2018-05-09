package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.io.IOException;
import java.lang.reflect.Array;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.*;


/**
 * This abstract class provides basic processing of messages
 */
public abstract class AbstractMessage implements Message {
    private Map<String, Object> claims;
    private Map<String, Object> header;
    private String input;
    private Error error = null;
    private boolean verified = false;
    protected ObjectMapper mapper = new ObjectMapper();

    protected AbstractMessage() {
        this(Collections.<String, Object>emptyMap());
    }

    protected AbstractMessage(Map<String, Object> claims) {
        this.claims = claims;
    }

    /**
     * @param input the urlEncoded String representation of a message
     */
    public void fromUrlEncoded(String input) throws MalformedURLException, IOException, InvalidClaimException {
        this.reset();
        this.input = input;
        String msgJson = StringUtils.newStringUtf8(Base64.decodeBase64(input));
        AbstractMessage msg = mapper.readValue(msgJson, this.getClass());
        this.claims = msg.getClaims();
    }

    /**
     * Takes the claims of this instance of the AbstractMessage class and serializes them
     * to an urlEncoded string
     *
     * @return an urlEncoded string
     */
    public String toUrlEncoded() throws SerializationException, JsonProcessingException {
        String jsonMsg = mapper.writeValueAsString(this);
        String urlEncodedMsg = Base64.encodeBase64URLSafeString(jsonMsg.getBytes(StandardCharsets.UTF_8));
        return urlEncodedMsg;
    }

    /**
     * Logic to extract from the JSON string the values
     * @param input The JSON String representation of a message
     */
    public void fromJson(String input) throws InvalidClaimException {
        this.reset();
        this.input = input;
        try {
            AbstractMessage msg = mapper.readValue(input, this.getClass());
            this.claims = msg.getClaims();
            System.out.println(this.claims);
        } catch (JsonGenerationException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Takes the claims of this instance of the AbstractMessage class and serializes them
     * to a json string
     *
     * @return a JSON String representation in the form of a hashMap mapping string -> string
     */
    public String toJson() throws SerializationException, JsonProcessingException {
        String jsonMsg = mapper.writeValueAsString(this);
        if (this.error != null) {
            throw new SerializationException("Error present cannot serialize message");
        }
        return jsonMsg;
    }

    /**
     * @param input the jwt String representation of a message
     */
    public void fromJwt(String input) throws IOException {
        this.reset();
        this.input = input;
        String[] parts = MessageUtil.splitToken(input);
        String headerJson;
        String payloadJson;
        try {
            headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
            payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        }
        this.header = mapper.readValue(headerJson, Map.class);
        this.claims = mapper.readValue(payloadJson, Map.class);
    }

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param algorithm the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimException
     */
    public String toJwt(Algorithm algorithm) throws
            JsonProcessingException, SerializationException {
        header.put("alg", algorithm.getName());
        header.put("typ", "JWT");
        String signingKeyId = algorithm.getSigningKeyId();
        if (signingKeyId != null) {
            header.put("kid", signingKeyId);
        }
        JWTCreator.Builder newBuilder = JWT.create().withHeader(this.header);
        for (String claimName: claims.keySet()){
            // TODO this needs to be extended for all claim types
            Object value = claims.get(claimName);
            if (value instanceof Boolean) {
                newBuilder.withClaim(claimName, (Boolean) value);
            } else if (value instanceof  String) {
                newBuilder.withClaim(claimName, (String) value);
            } else if (value instanceof Date) {
                newBuilder.withClaim(claimName, (Date) value);
            } else if (value instanceof Long) {
                newBuilder.withClaim(claimName, (Long) value);
            }
        }
        return newBuilder.sign(algorithm);
    }

    /**
     * verify that the required claims are present
     * @return whether the verification passed
     */
    protected boolean verify() throws InvalidClaimException {
        //This method will set error if verification fails
        List<String> errorMessages = new ArrayList<String>();
        StringBuilder errorSB = new StringBuilder();

        List<String> reqClaims = getRequiredClaims();
        if (reqClaims != null && this.claims.isEmpty()){
            errorMessages.add("Not all of the required claims for this message type are present");
        } else {
            if (reqClaims != null) {
                for (String req : reqClaims) {
                    if (!claims.containsKey(req)) {
                        errorSB.append(" " + req);
                    }
                }
                if (errorSB.length() != 0) {
                    errorMessages.add("Message is missing required claims:" + errorSB.toString());
                }
            }

            errorSB = new StringBuilder();

            for (String claimName : claims.keySet()) {
                // if knownClaim, validate claim
                if (ClaimsValidator.isKnownClaim(claimName)) {
                    try {
                        ClaimsValidator.validate(claimName, claims.get(claimName), fetchMessageType());
                    } catch (com.auth0.jwt.exceptions.InvalidClaimException e) {
                        errorMessages.add(claimName + "is an invalid claim. ");
                    }
                } else {
                    if (!allowCustomClaims()) {
                        claims.remove(claimName);
                    }
                }
            }

        }

        if (!errorMessages.isEmpty()) {
            for (String err : errorMessages) {
                errorSB.append(err);
            }
            this.error = new Error(errorMessages);
            throw new InvalidClaimException(errorSB.toString());
        }
        return false;
    }

    /**
     * @return Boolean whether this message subclass allows for custom claims
     */
    public abstract boolean allowCustomClaims();

    /**
     * @return Error an object representing the error status of claims verification
     */
    public Error getError() {
        return error;
    }

    /**
     * @return List of the list of claims for this messsage
     */
    public Map<String, Object> getClaims() throws InvalidClaimException {
            verify();
            return this.claims;
    }

    /**
     * @return List of the list of standard optional claims for this messsage type
     */
    protected List<String> getOptionalClaims(){
        return Collections.emptyList();
    }

    /**
     * add the claim to this instance of message
     * @param name the name of the claim
     * @param value the value of the claim to add to this instance of Message
     */
    public void addClaim(String name, Object value) {
        this.claims.put(name, value);
    }

    /**
     * @return List of the list of standard required claims for this messsage type
     */
    abstract protected List<String> getRequiredClaims();

    protected void reset(){
        this.input = null;
        this.claims = null;
        this.error = null;
        this.verified = false;
    }

    /**
     * @return enum Name of the message subtype
     */
    abstract protected MessageType fetchMessageType();

    /**
     * @return boolean for whether there is an error in verification
     */
    public boolean hasError(){
        return this.error != null;
    }

    @Override
    public String toString() {
        //Override to return user friendly value
        return super.toString();
    }
}