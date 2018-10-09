
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.spec.SecretKeySpec;
import java.util.*;

/**
 * JSON Web key representation of a Symmetric key.
 * According to RFC 7517 a JWK representation of a symmetric key can look like
 * this::
 * {
 *  "kty":"oct",
 *  "alg":"A128KW",
 *  "k":"GawgguFyGrWKav7AX4VKUg"
 * }
 */
public class SYMKey extends Key{

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
            put("", "HmacSHA512"); // for default
        }
    };

    /**
     * Constructs a new SYMKey instance
     * Can just pass the base64url encoded string components of the symmetric key
     * or the javax.crypto.spec.SecretKeySpec instance
     *
     * The name of parameters used in this class are the same as
     * specified in the RFC 7517.
     *
     * @param alg algorithm that this Key is used for
     * @param use The intended use of this Key ("sig" or "enc")
     * @param kid kid key ID
     * @param key the javax.crypto.spec.SecretKeySpec instance for this SYMKey
     * @param x5c array of certificates. The certificate with the key must be first.
     * @param x5t base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate
     * @param x5u URI that points to a resource for an X.509 public key certificate or chain
     * @param k base64url encoded secret key
     * @param args
     * @throws ValueError
     * @throws DeserializationNotPossible
     */
    public SYMKey(String alg, String use, String kid, java.security.Key key, String[] x5c,
                  String x5t, String x5u, String k, Map<String,String> args) throws ValueError, DeserializationNotPossible{
        super("oct", alg, use, kid, x5c, x5t, x5u, key, args);
        members.add("k");
        required.add("k");
        if(Utils.isNullOrEmpty(alg)) {
            this.alg = "";
        } else {
            if(!alg2HmacAlg.containsKey(this.alg))
                throw new ValueError("Invalid alg");
        }
        this.k = Utils.isNullOrEmpty(k) ? "" : k;
        if(this.key == null) {
            deserialize();
        }
    }

    /**
     * Constructs a new instance using only the usage and javax.crypto.spec.SecretKeySpec instance
     * @param use
     * @param key
     * @throws ValueError
     * @throws DeserializationNotPossible
     */
    public SYMKey(String use, java.security.Key key) throws ValueError, DeserializationNotPossible {
        this("", use, "", key, null, "", "", "", null);
    }

    /**
     * Creates SymKey using only the usage and base64url encode secret
     * @param use sig or enc
     * @param k base64urlencode key bytes
     * @throws ValueError
     */
    public SYMKey(String use, String k) throws ValueError, DeserializationNotPossible{
        this("", use, "", null, null, "", "", k, null);
    }


    @Override
    public void deserialize() throws DeserializationNotPossible {
        if(key == null) {
            if(Utils.isNullOrEmpty(k))
                throw new DeserializationNotPossible();
            byte[] secretBytes = Base64.decodeBase64(k);
            key = new SecretKeySpec(secretBytes, alg2HmacAlg.get(alg));
        }
    }

    @Override
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

    /**
     * Gets the javax.crypto.spec.SecretKeySpec internal instance
     *
     * @return javax.crypto.spec.SecretKeySpec of this SYMKeys intenal key
     * @throws DeserializationNotPossible
     */
    public java.security.Key encryptionKey() throws DeserializationNotPossible {
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
    public boolean equals(Object other) {
        try {
            if(other instanceof  SYMKey) {
                SYMKey symOther = (SYMKey) other;
                if(key == null) {
                    deserialize();
                }
                if(symOther.key == null) {
                    symOther.deserialize();
                }
                if(key instanceof SecretKeySpec && symOther.key instanceof SecretKeySpec) {
                    if(!Utils.isNullOrEmpty(k)) {
                        return k.equals(symOther.k);
                    }
                }
            }
        } catch (DeserializationNotPossible e) {

        }

        return false;
    }
}

