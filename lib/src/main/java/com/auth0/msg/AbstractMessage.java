package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * This abstract class provides basic processing of messages
 */
public abstract class AbstractMessage implements Message {
    private Map<String, Object> claims;
    private Map<String, Object> header; // There are only headers when fromJwt/ToJwt is called
    private String input;
    private Error error = null;
    private boolean verified = false;
    ObjectMapper mapper = new ObjectMapper();

    protected AbstractMessage() {
        this(Collections.<String, Object>emptyMap());
    }

    protected AbstractMessage(Map<String, Object> claims) {
        this.claims = claims;
    }

    /**
     * @param input the urlEncoded String representation of a message
     */
    public void fromUrlEncoded(String input) throws MalformedURLException, IOException {
        this.input = input;
        String msgJson = StringUtils.newStringUtf8(Base64.decodeBase64(input));
        // Convert JSON string to Object
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
    public void fromJson(String input) {
        this.input = input;
        try {
            // Convert JSON string to Object
//            TypeReference<HashMap<String, String>> typeRef
//                    = new TypeReference<HashMap<String, String>>() {};
            AbstractMessage msg = mapper.readValue(input, this.getClass());
            this.claims = msg.getClaims();
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
            throw new InvalidClaimsException("Error present cannot serialize message");
        }
        return jsonMsg;
    }

    /**
     * @param input the jwt String representation of a message
     * @param KeyJar that might contain the necessary key
     */
    public void fromJwt(String input, KeyJar jar) {
        this.input = input;

        //This will have logic to parse Jwt to claims
    }

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param KeyJar the signing keyjar
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimsException
     */
    public String toJwt(KeyJar keyjar, Algorithm algorithm) throws
            InvalidClaimsException, SerializationException {
        header.put("alg", algorithm.getName());
        header.put("typ", "JWT");
        String signingKeyId = algorithm.getSigningKeyId();
        if (signingKeyId != null) {
            header.put("kid", signingKeyId);
        }
//        JWTCreator.Builder newBuilder = JWT.create().withHeader(this.header);
//        for (Claim claimKey: claims.keySet()){
//            newBuilder.withClaim(claimKey.name, (claimKey.type) claims.get(claimKey));
//        }
        return null;
    }

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param Key the signing key
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimsException
     */
    public String toJwt(Key key, Algorithm algorithm) throws InvalidClaimsException, SerializationException {
        return null;
    }

    /**
     * verify that the required claims are present
     * @return whether the verification passed
     */
    protected boolean verify() {
        //This method will set error if verification fails
        List<String> errors = new ArrayList<String>();

        List<String> reqClaims = getRequiredClaims();
        if (!reqClaims.isEmpty() && this.claims.isEmpty()){
            errors.add("The required claims are missing");
            return false;
        }

        StringBuilder errorSB = new StringBuilder();
        for (String req: reqClaims) {
            if (!claims.containsKey(req)) {
                errors.add("This message is missing required claim: " + req);
                errorSB.append(req);
            }
        }

        if (errorSB.length() != 0) {
            errors.add("Message is missing required claims:" + errorSB.toString());
            return false;
        }

        List<String> customClaims = new ArrayList<String>();
        for(String claimName : claims.keySet()) {
            // if knownClaim, validate claim
            if (ClaimsValidator.isKnownClaim(claimName)) {
                Boolean valid = ClaimsValidator.validate(claimName, claims.get(claimName), getMessageType());
                if (!valid) {
                    errors.add(claimName + "is an invalid claim");
                }
            } else {
                customClaims.add(claimName);
            }
        }
        if (!errors.isEmpty()) {
            String aggregateError = "";
            for (String err: errors){
                aggregateError += err;
            }
            throw new InvalidClaimsException(aggregateError);
        }
        return false;
    }

    public abstract MessageType getMessageType();

    /**
     * add the claim to this instance of message
     * @param String the name of the claim
     * @param Object the value of the claim to add to this instance of Message
     * @return a Message representation of the Json
     */
    public void addString(String name, Object value) {
        // verify 'name’ is a valid claim and then check the type is valid before adding
    }

    /**
     * @return Error an object representing the error status of claims verification
     */
    public Error getError() {
        return error;
    }

    /**
     * @return List of the list of claims for this messsage
     */
    public Map<String, Object> getClaims(){
//        verify();
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
     * @param String the name of the claim
     * @param Object the value of the claim to add to this instance of Message
     * @return a Message representation of the Json
     */
    public void addClaim(String name, Object value) {
        // verify 'name’ is a valid claim and then check the type is valid before adding
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

    @Override
    public String toString() {
        //Override to return user friendly value
        return super.toString();
    }
}