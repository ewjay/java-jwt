
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Basic JSON Web key class. Jason Web keys are described in
 * RFC 7517 (https://tools.ietf.org/html/rfc7517).
 * The name of parameters used in this class are the same as
 * specified in RFC 7518 (https://tools.ietf.org/html/rfc7518).
 */
public abstract class Key {

    final private static Logger logger = LoggerFactory.getLogger(Key.class);
    protected String kty;
    protected String alg;
    protected String use;
    protected String kid;
    protected String[] x5c;
    protected String x5t;
    protected String x5u;
    protected java.security.Key key;
    protected long inactiveSince;
    protected Map<String, String> args;
    protected Set<String> longs = new HashSet<String>();
    protected Set<String> members = new HashSet<String>
        (Arrays.asList("kty", "alg", "use", "kid", "x5c", "x5t", "x5u"));
    protected Set<String> publicMembers = new HashSet<String>
        (Arrays.asList("kty", "alg", "use", "kid", "x5c", "x5t", "x5u"));
    protected Set<String> required = new HashSet<String>(Arrays.asList("kty"));

    public Key(String kty, String alg, String use, String kid, String[] x5c, String x5t,
               String x5u, java.security.Key key, Map<String, String> args) {
        this.kty = Utils.isNullOrEmpty(kty) ? "" : kty;
        this.alg = Utils.isNullOrEmpty(alg) ? "" : alg;
        this.use = Utils.isNullOrEmpty(use) ? "" : use;
        this.kid = Utils.isNullOrEmpty(kid) ? "" : kid;
        if(x5c != null)
            this.x5c = x5c;
        else
            this.x5c = new String[0];
        this.x5t = Utils.isNullOrEmpty(x5t) ? "" : x5t;
        this.x5u = Utils.isNullOrEmpty(x5u) ? "" : x5u;
        this.inactiveSince = 0;
        this.key = key;
        if(args != null)
            this.args = args;
        else
            this.args = new HashMap<>();
    }

    public Key() {
        this("", "", "", "", null, "", "", null, null);
    }

    public String[] getX5c() {
        return x5c;
    }

    public void setX5c(String[] x5c) {
        if(x5c == null)
            this.x5c = new String[0];
        else
            this.x5c = x5c;
    }

    public String getX5t() {
        return x5t;
    }

    public void setX5t(String x5t) {
        this.x5t = Utils.isNullOrEmpty(x5t) ? "" : x5t;
    }

    public String getX5u() {
        return x5u;
    }

    public void setX5u(String x5u) {
        this.x5u = Utils.isNullOrEmpty(x5u) ? "" : x5u;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = Utils.isNullOrEmpty(kty) ? "" : kty;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = Utils.isNullOrEmpty(kty) ? "" : alg;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = Utils.isNullOrEmpty(use) ? "" :use;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = Utils.isNullOrEmpty(kid) ? "" :kid;
    }

    public void setInactiveSince() {
        this.inactiveSince = System.currentTimeMillis();
    }

    public void setInactiveSince(long now) {
        this.inactiveSince = now;
    }

    public long getInactiveSince() {
        return inactiveSince;
    }

    public Map<String, Object> toDict() {
        try {
            Map<String, Object> hmap = serialize();
            for (String key : args.keySet()) {
                hmap.put(key, args.get(key));
            }
            return hmap;

        } catch (SerializationNotPossible e) {

        }
        return new HashMap<>();
    }

    public Map<String, Object> common() {
        Map<String, Object> args = new HashMap<>();
        args.put("kty", kty);

        if (!Utils.isNullOrEmpty(use)) {
            args.put("use", use);
        }
        if (!Utils.isNullOrEmpty(kid)) {
            args.put("kid", kid);
        }
        if (!Utils.isNullOrEmpty(alg)) {
            args.put("alg", alg);
        }
        return args;
    }

    public String toString() {
        return this.toDict().toString();
    }

    public void setProperties(Map<String, Object> props) {
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if(key.equals("kty")) {
                kty =  Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("alg")) {
                alg = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("use")) {
                use = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("kid")) {
                kid = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("x5t")) {
                x5t = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("x5u")) {
                x5u = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("x5c")) {
                if(x5c == null)
                    x5c = new String[0];
                else
                    x5c = (String[]) val;
            } else {
                args.put(key, Utils.isNullOrEmpty((String) val) ? "" : (String) val );
            }
        }
    }


    /**
     *
     * Verify that the information gathered from the on-the-wire
     * representation is of the right type.
     * This is supposed to be run before the info is deserialized.
     * @return boolean
     * @throws HeaderError
     */
    public boolean verify() throws HeaderError {

        /**

         Python code
         checks whether values are strings
         Java constructor only accept strings


        for param in self.longs:
            item = getattr(self, param)
            if not item or isinstance(item, str):
                continue

            if isinstance(item, bytes):
                item = item.decode('utf-8')
                setattr(self, param, item)

            try:
                _ = base64url_to_long(item)
            except Exception:
                return False
            else:
                if [e for e in ['+', '/', '='] if e in item]:
                    return False

        if self.kid:
            if not isinstance(self.kid, str):
                raise HeaderError("kid of wrong value type")
        return True

         */

        /*
        Object item = null;
        for (String key : longs.keySet()) {

            try {
                item = this.getClass().getField(key).get(this);
            } catch (Exception e1) {
                logger.error("Field " + key + " doesn't exist");
            }
            if (item == null || item instanceof Number) {
                continue;
            }

            if (item instanceof Bytes) {
                //item = item.decode('utf-8') ???
                //TODO
            }

            try {
                base64URLToLong(item);
            } catch (Exception e) {
                return false;
            } finally {
                for(String sign : new ArrayList<>(Arrays.asList("+", "/", "="))) {
                    if(((String) item).contains(sign)) {
                        return false;
                    }
                }
            }


        }
        */

        return true;
    }

    public boolean equals(Object other) {
        try {
            Assert.assertTrue(other instanceof Key);
            Key otherKey = (Key) other;
            Assert.assertEquals(this.getKty(), otherKey.kty);
            Assert.assertEquals(this.getAlg(), otherKey.alg);
            Assert.assertEquals(this.getUse(), otherKey.use);
            Assert.assertEquals(this.getKid(), otherKey.kid);
            Assert.assertEquals(this.getX5c(), otherKey.x5c);
            Assert.assertEquals(this.getX5t(), otherKey.x5t);
            Assert.assertEquals(this.getX5u(), otherKey.x5u);
        } catch (AssertionError error) {
            return false;
        }
        return true;

    }

    public List<String> getKeys() {
        return new ArrayList<>(this.toDict().keySet());
    }


    /**
     * Gets the JWK digest of the key using the specified digest algotithm
     * @param hashFunction Hash function used to perform the digest
     * @param members members of the key to use; null to use default required key members
     * @return byte[] of digest
     * @throws NoSuchAlgorithmException, SerializationNotPossible
     */
    public byte[] thumbprint(String hashFunction, List<String> members) throws
            NoSuchAlgorithmException, SerializationNotPossible {
        if(members == null)
            members = Arrays.asList(this.required.toArray(new String[0]));
        String[] membersArray = members == null ? this.required.toArray(new String[0]) :
                members.toArray(new String[0]);
        Arrays.sort(membersArray);
        Map<String, Object> ser = this.serialize();
        StringBuilder sb = new StringBuilder().append('{');
        for (String elem : membersArray) {
            if(ser.containsKey(elem)) {
                // TODO check if ser.get(elem) is non-string e.g. array, Integer etc.
                sb.append(String.format("\"%s\":\"%s\",", elem, ser.get(elem)));
            }
        }
        sb.deleteCharAt(sb.length() -1).append('}');
        MessageDigest md = MessageDigest.getInstance(hashFunction);
        md.update(StringUtils.getBytesUtf8(sb.toString()));
        return md.digest();
    }

    /**
     * Returns the base64url encoded digest of the key
     * @param hashFunction digest algorithm to perform digest
     * @return String base64urlencoded string of thumbprint hash
     * @throws NoSuchAlgorithmException SerializationNotPossible
     */
    public String thumbprint(String hashFunction)
        throws NoSuchAlgorithmException, SerializationNotPossible {
        return Base64.encodeBase64URLSafeString(thumbprint(hashFunction, null));
    }

    public void addKid() {
        try {
            this.kid = thumbprint("SHA-256");
        }
        catch(NoSuchAlgorithmException | SerializationNotPossible e) {
        }
    }

    /**
     * Checks whether this is a private key
     * @return boolean Indicates whether this is private key
     */
    abstract public boolean isPrivateKey();


    /**
     * Checks whether this is a public key
     * @return boolean Indicates whether this is public key
     */
    public boolean isPublicKey() {
        return !isPrivateKey();
    }




    /**
     * map key characteristics into attribute values that can be used
     * to create an on-the-wire representation of the key
     * @return Map of object and internal values
     */

    public abstract Map<String, Object> serialize(boolean isPrivate)
        throws SerializationNotPossible;


    /**
     * map key characteristics into attribute values that can be used
     * to create an on-the-wire representation of the public key
     * @return Map of object and internal values of a public key
     */

    public Map<String, Object>  serialize() throws SerializationNotPossible {
        return serialize(false);
    };

    /**
     * Starting with information gathered from the on-the-wire representation
     * initiate an appropriate key.
     */
    public abstract void deserialize() throws DeserializationNotPossible;


    public abstract java.security.Key getKey(Boolean isPrivate) throws ValueError;


    public static boolean cmpPublicNumbers() {
        // TODO
        return true;
    }

    public static boolean cmpPrivateNumbers() {
        // TODO
        return true;
    }


}

