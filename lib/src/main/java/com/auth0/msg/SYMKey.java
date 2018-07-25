
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.spec.SecretKeySpec;
import java.util.*;

public class SYMKey extends Key{

    final private static Logger logger = LoggerFactory.getLogger(SYMKey.class);
    private String k;
    private static Map<String,Integer> alg2Keylen = new HashMap<String,Integer>(){{
        put("A128KW", 16);
        put("A192KW", 24);
        put("A256KW", 32);
        put("HS256", 32);
        put("HS384", 48);
        put("HS512", 64);
    }};

    private  static Map<String, String> alg2HmacAlg = new HashMap<String, String>(){
        {
            put("HS256", "HmacSHA256");
            put("HS384", "HmacSHA384");
            put("HS512", "HmacSHA512");
        }
    };

    public SYMKey(String alg, String use, String kid, java.security.Key key, String[] x5c,
                  String x5t, String x5u, String k, Map<String,String> args) throws ValueError{
        super("oct", alg, use, kid, x5c, x5t, x5u, key, args);
        members.add("k");
        required.add("k");
        if(Utils.isNullOrEmpty(alg))
            this.alg = "HS256";
        if(!alg2HmacAlg.containsKey(this.alg))
            throw new ValueError("Invalid alg");
        this.k = k;
        if(this.key == null) {
            deserialize();
        }
    }

    public SYMKey(String use) throws ValueError{
        this("", use, "", null, null, "", "", "", null);
    }

    /**
     * Creates SymKey
     * @param use sig or enc
     * @param k base64urlencode key bytes
     * @throws ValueError
     */
    public SYMKey(String use, String k) throws ValueError{
        this("", use, "", null, null, "", "", k, null);
    }


    @Override
    public void deserialize() {
        if(key == null) {
            byte[] secretBytes = Base64.decodeBase64(k);
            key = new SecretKeySpec(secretBytes, alg2HmacAlg.get(alg));
        }
    }

    public Map<String,Object> serialize(boolean isPrivate) throws SerializationNotPossible{
        Map<String,Object> args = common();
        if(!Utils.isNullOrEmpty(k))
            args.put("k", k);
        else if(key != null) {
            SecretKeySpec secretKeySpec = (SecretKeySpec) key;
            byte[] secretBytes = secretKeySpec.getEncoded();
            if(secretBytes == null)
                throw new SerializationNotPossible();
            args.put("k", Base64.encodeBase64URLSafeString(secretBytes));
        }
        return args;
    }

    public java.security.Key encryptionKey() {
        if(this.key == null) {
            deserialize();
        }
      return key;
    }

    @Override
    public boolean isPrivateKey() {
        return true;
    }

    @Override
    public boolean isPublicKey() {
        return true;
    }

    @Override
    public java.security.Key getKey(Boolean isPrivate) {
        return key;
    }

    @Override
    public void setProperties(Map<String, Object> props) {
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if(key.equals("k")) {
                k = (String) val;
            } else {
                super.setProperties(props);
            }
        }
    }
}

