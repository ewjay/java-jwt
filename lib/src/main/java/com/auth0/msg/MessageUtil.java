package com.auth0.msg;

import java.util.HashMap;
import java.util.Map;

public class MessageUtil {
    /**
     * Returns a hashmap representation of the contents of the urlEncoded string
     * which is passed in as a parameter
     *
     * @param urlEncoded the urlEncoded String representation of a message
     * @return a map of the key value pairs encoded in the string parameter
     */
    private Map<String, Object> claims;
    public MessageUtil(Map<String, Object> claims){
        this.claims = claims;
    }
    public static Map<String, Object> claimsFromUrlEncoded(String urlEncoded) throws Exception {
        //Logic to extract from the string the values
        Map<String, Object> values = new HashMap<String, Object>();
        return values;
    }
    public Map<String, Object> getClaims(){
        return this.claims;
    }
    /**
     * @param String endpoint to base the request url on
     * @return a String for the representation of the formatted request
     */
    public String getRequestWithEndpoint(String authorizationEndpoint) {
        return null;
    }

}
