package com.auth0.msg;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Map;

/**
 * This interface all the methods related to message processing.
 */
public interface Message {

    /**
     * Serialize the content of this instance (the claims map) into a JSON object
     * @return a JSON String representation of the message
     * @throws SerializationException
     */
    String toJson() throws SerializationException, JsonProcessingException;

    /**
     * Serialize the content of the claims map into an UrlEncoded string
     * @return a urlEncoded string
     * @throws SerializationException
     */
    String toUrlEncoded() throws SerializationException, JsonProcessingException;

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param KeyJar the signing keyjar
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimException
     */
    String toJwt(KeyJar jar, Algorithm algorithm) throws SerializationException, JsonProcessingException;

    /**
     * Logic to extract from the string the values
     * @param input The JSON String representation of a message
     */
    void fromJson(String input) throws InvalidClaimException;

    /**
     * @param input the urlEncoded String representation of a message
     */
    void fromUrlEncoded(String input) throws MalformedURLException, IOException, InvalidClaimException;

    /**
     *
     * @param input the jwt String representation of a message
     * @param KeyJar that might contain the necessary key
     */
    void fromJwt(String input, KeyJar jar) throws InvalidClaimException;

    /**
     *
     * @param name of the claim
     * @param value of the claim
     */
    void addClaim(String name, Object value);

    /**
     *
     * @return Map of claims
     * @throws InvalidClaimException
     */
    Map<String, Object> getClaims() throws InvalidClaimException;
    /**
     * @return the error object representing an error in verification
     */
    Error getError();

    /**
     * @return boolean for whether there is an error in verification
     */
    boolean hasError();
}
