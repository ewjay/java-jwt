
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.TypeError;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.slf4j.LoggerFactory;
import java.security.KeyException;
import java.util.*;
import java.util.logging.Logger;

public class KeyJar {

    private boolean verifySSL;
    private float removeAfter;
    private Map<String,List<KeyBundle>> issuerKeys;
    final private static org.slf4j.Logger logger = LoggerFactory.getLogger(KeyJar.class);

    public KeyJar(boolean verifySSL, int removeAfter) {
        this.verifySSL = verifySSL;
        this.removeAfter = removeAfter;
        issuerKeys = new HashMap<String, List<KeyBundle>>();
    }

    public KeyJar() throws ImportException {
        this(true, 3600);
    }

    public KeyBundle addUrl(String owner, String url, Map<String,String> args) throws KeyException, ImportException {
        if(url == null || url.isEmpty()) {
            throw new KeyException("No jwksUri");
        }

        KeyBundle keyBundle;
        if(url.contains("/localhost:") || url.contains("/localhost/")) {
            keyBundle = new KeyBundle(url, false);
        } else {
            keyBundle = new KeyBundle(url, verifySSL);
        }

        addKeyBundle(owner, keyBundle);

        return keyBundle;
    }

    /**
     * Add Symmetric Key to Jar using
     * @param owner
     * @param k symmetric key bytes
     * @param usage list of uses for the key
     * @throws ImportException
     */
    public void addSymmetricKey(String owner, byte[] k, List<String> usage) throws ImportException {
        if(!issuerKeys.containsKey(owner)) {
            issuerKeys.put(owner, new ArrayList<KeyBundle>());
        }
        String b64Key = Base64.encodeBase64URLSafeString(k);
        if(usage == null || usage.isEmpty()) {
            HashMap<String, Object> jwk = new HashMap<String, Object>();
            jwk.put("kty", "oct");
            jwk.put("k", b64Key);
            ArrayList<Map<String, Object>> keyList =
                    new ArrayList<Map<String, Object>>(Arrays.asList(jwk));
            KeyBundle kb = new KeyBundle(keyList);
            addKeyBundle(owner, kb);
        } else {
            ArrayList<Map<String, Object>> keyList =
                    new ArrayList<Map<String, Object>>();

            for(String use : usage) {
                HashMap<String, Object> jwk = new HashMap<String, Object>();
                jwk.put("kty", "oct");
                jwk.put("k", b64Key);
                jwk.put("use", use);
                keyList.add(jwk);
            }
            KeyBundle kb = new KeyBundle(keyList);
            addKeyBundle(owner, kb);
        }
    }

    public void addKeyBundle(String owner, KeyBundle keyBundle) {
        List<KeyBundle> kbList;
        if(issuerKeys.get(owner) == null) {
            kbList = new ArrayList<>(Arrays.asList(keyBundle));
        } else {
            kbList = issuerKeys.get(owner);
            kbList.add(keyBundle);
        }
        issuerKeys.put(owner, kbList);
    }

    public Map<String, List<KeyBundle>> getBundles() {
        return issuerKeys;
    }

    public void setBundle(String owner, List<KeyBundle> kbList) {
        issuerKeys.put(owner, kbList);
    }

    public List<Key> getKeys(String keyUse, String keyType, String owner, String kid, Map<String,String> args) {
        String use;
        if(keyUse.equals("dec") || keyUse.equals("enc")) {
            use = "enc";
        } else {
            use = "sig";
        }

        List<KeyBundle> keyBundleList = null;
        if(!Utils.isNullOrEmpty(owner)) {
            keyBundleList = this.issuerKeys.get(owner);

            if(keyBundleList == null) {
                if(owner.endsWith("/")) {
                    keyBundleList = this.issuerKeys.get(owner.substring(0, owner.length()-1));
                } else {
                    keyBundleList = this.issuerKeys.get(owner+"/");
                }
            }
        } else {
            keyBundleList = this.issuerKeys.get(owner);
        }

        if(keyBundleList == null) {
            return new ArrayList<>();
        }

        List<Key> keyListReturned = new ArrayList<>();
        List<Key> keyList = new ArrayList<>();
        for(KeyBundle keyBundle : keyBundleList) {
            if(!Utils.isNullOrEmpty(keyType)) {
                keyList = keyBundle.get(keyType);
            } else {
                keyList = keyBundle.getKeys();
            }

            for(Key key : keyList) {
                if(key.getInactiveSince() == 0 && !keyUse.equals("sig")) {
                    continue;
                }
                if(key.getUse() != null || use.equals(key.getUse())) {
                    if(kid != null) {
                        if(kid.equals(key.getKid())) {
                            keyListReturned.add(key);
                            break;
                        } else
                            continue;
                    } else {
                        keyListReturned.add(key);
                    }
                }
            }
        }

        // if elliptic curve have to check I have a key of the right curve
        String name;
        if(keyType.equals("EC") && args.containsKey("alg")) {
            name = "P-" + args.get("alg").substring(2);
            List<Key> tempKeyList = new ArrayList<>();
            for(Key key : keyList) {
                ECKey ecKey = (ECKey) key;
                if(!name.equals(ecKey.getCrv()))
                    continue;
                else
                    tempKeyList.add(key);
            }
            keyList = tempKeyList;
        }

        if(use.equals("enc") && keyType.equals("oct") && !Utils.isNullOrEmpty(owner)) {
            for(KeyBundle keyBundle : this.issuerKeys.get("")) {
                for(Key key : keyBundle.get(keyType)) {
                    if(key.getUse() == null || key.getUse().equals(use)) {
                        keyList.add(key);
                    }
                }
            }
        }

        return keyList;
    }

    public List<Key> getSigningKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("sig", keyType, owner, kid, args);
    }

    public List<Key> getVerifyKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("ver", keyType, owner, kid, args);
    }

    public List<Key> getEncryptKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("enc", keyType, owner, kid, args);
    }

    public List<Key> getDecryptKey(String keyType, String owner, String kid, Map<String,String> args) {
        return getKeys("dec", keyType, owner, kid, args);
    }

    public List<Key> keysByAlgAndUsage(String issuer, String algorithm, String usage) {
        String keyType;
        if(usage.equals("sig") || usage.equals("ver")) {
            keyType = algorithmToKeytypeForJWS(algorithm);
        } else {
            keyType = algorithmToKeytypeForJWE(algorithm);
        }

        return getKeys(usage, keyType, issuer, null, null);
    }

    public List<Key> getIssuerKeys(String issuer) {
        List<Key> keyList = new ArrayList<>();
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            keyList.addAll(keyBundle.getKeys());
        }
        return keyList;
    }

    private String algorithmToKeytypeForJWS(String algorithm) {
        if(algorithm == null || algorithm.toLowerCase().equals("none")) {
            return "none";
        } else if(algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            return "RSA";
        } else if(algorithm.startsWith("HS") || algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ES") || algorithm.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return null;
        }
    }

    private String algorithmToKeytypeForJWE(String algorithm) {
        if(algorithm.startsWith("RSA")) {
            return "RSA";
        } else if(algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ECDH")) {
            return "EC";
        } else {
            return null;
        }
    }

    public List<String> getOwners() {
       return Arrays.asList(issuerKeys.keySet().toArray(new String[0]));
    }

    public String matchOwner(String url) throws KeyException {
        for(String key : this.issuerKeys.keySet()) {
            if(url.startsWith(key)) {
                return key;
            }
        }

        throw new KeyException(String.format("No keys for %s", url));
    }

    public void loadKeys(Map<String,Object> pcr, String issuer, boolean shouldReplace) {
        logger.debug("loading keys for issuer: " + issuer);

        if(shouldReplace || !this.issuerKeys.keySet().contains(issuer)) {
            this.issuerKeys.put(issuer, new ArrayList<KeyBundle>());
        }
        String jwksUri = (String) pcr.get("jwks_uri");
        if(!Utils.isNullOrEmpty(jwksUri)) {

        } else {
            Object jwks = (String) pcr.get("jwks");
            if(jwks != null) {
                if(jwks instanceof Map) {
                    Map<String, Object> keys = (Map<String, Object>) ((Map)jwks).get("keys");
                    if(keys != null) {
                        try {
                            addKeyBundle(issuer, new KeyBundle(Arrays.asList(keys)));
                        }
                        catch(ImportException e) {
                        }
                    }
                }
            }
        }
    }

    public KeyBundle find(String source, String issuer) {
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            if(keyBundle.getSource().equals(source)) {
                return keyBundle;
            }
        }

        return null;
    }

    public Map<String,List<Map<String, Object>>> exportsJwks(boolean isPrivate, String issuer) {
        List<Map<String, Object>> keys = new ArrayList<>();
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            for(Key key : keyBundle.getKeys()) {
                if(key.getInactiveSince() == 0) {
                    try {
                        keys.add(key.serialize(isPrivate));
                    }
                    catch (SerializationNotPossible e) {
                    }
                }
            }
        }

        Map<String,List<Map<String, Object>>> keysMap = new HashMap<>();
        keysMap.put("keys", keys);
        return keysMap;
    }

    public String exportJwksAsJson(boolean isPrivate, String issuer) {
        JSONObject json = new JSONObject(exportsJwks(isPrivate, issuer));
        return json.toJSONString();
    }

    public void importJwks(Map<String,Object> jwks, String issuer) throws ImportException {
        Object keysObj = jwks.get("keys");
        if(keysObj instanceof List) {
            List<Object> keysList = (List<Object>) jwks.get("keys");
            if(!keysList.isEmpty()) {
                if(keysList.get(0) instanceof Map) {
                    List<Map<String, Object>> keysMap = (List<Map<String, Object>>) keysList.get(0);
                    addKeyBundle(issuer, new KeyBundle(keysMap, "", 0, verifySSL, "jwk", "", null));
                }
            }
        }
    }

    public void importJwksAsJson(String js, String issuer) throws ParseException, ImportException{
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(js);
        importJwks(json, issuer);
    }

    public void removeOutdated(int when) throws TypeError {
        List<KeyBundle> keyBundleList;
        for(String owner : this.issuerKeys.keySet()) {
            keyBundleList = new ArrayList<>();
            for(KeyBundle keyBundle : this.issuerKeys.get(owner)) {
                keyBundle.removeOutdated(this.removeAfter, when);
                if(keyBundle.getLength() > 0) {
                    keyBundleList.add(keyBundle);
                }
            }

            if(keyBundleList.size() > 0) {
                this.issuerKeys.put(owner, keyBundleList);
            } else {
                this.issuerKeys.remove(owner);
            }
        }
    }

    public List<Key> addKey(List<Key> keys, String owner, String use, String keyType, String kid,
                            Map<String,List<String>> noKidIssuer, boolean allowMissingKid) {
        if(!this.issuerKeys.keySet().contains(owner)) {
            logger.error("Issuer " + owner + " not in keyjar");
            return keys;
        }

//        logger.debug("Key set summary for " + owner + " : " + keySummary(this, owner));

        if(kid != null) {
            for(Key key : this.getKeys(use, owner, kid, keyType, null)) {
                if(key != null && !keys.contains(key)) {
                    keys.add(key);
                }
            }
            return keys;
        } else {
            List<Key> keyList = this.getKeys(use, keyType, owner, "", null);
            if(keyList.size() == 0) {
                return keys;
            } else if(keyList.size() == 1) {
                if(!keys.contains(keyList.get(0))) {
                    keys.add(keyList.get(0));
                }
            } else if(allowMissingKid) {
                keys.addAll(keyList);
            } else if(noKidIssuer != null) {
                List<String> allowedKids = noKidIssuer.get(owner);
                if(allowedKids != null) {
                    for(Key key : keyList) {
                        if(allowedKids.contains(key.getKid())) {
                            keys.add(key);
                        }
                    }
                }
            }
        }
        return keys;
    }

//    public void getJwtVerifyKeys(JWT jwt, Map<String,String> args) {
//        List<Key> keyList = new ArrayList<>();
//        JWTParser converter = new JWTParser();
//        String keyType = algorithmToKeytypeForJWS(converter.parseHeader(jwttoString().getHeader().getAlgorithm().getName());
//        String kid = jwt.getHeader().;
//        String nki = args.get("no_kid_issuer");
//
//    }

    public void getJWTVerifyKeys(String jwt, Map<String, Object> args) {

    }

    public KeyJar copy() throws ImportException {
        KeyJar keyJar = new KeyJar();
        for(String owner : this.issuerKeys.keySet()) {
            for(KeyBundle kb : issuerKeys.get(owner)) {
                keyJar.addKeyBundle(owner, kb.copy());
            }
         }
        return keyJar;
    }

    public static KeyJar buildKeyJar(Map<String, Object> keyConf, String kidTemplate, KeyJar keyJar, Map<String, Object> kidd) {

        return null;
    }

    public static KeyJar initKeyJar(String publicPath, String privatePath, String keyDefs, String issuer) {

        return null;
    }
}

