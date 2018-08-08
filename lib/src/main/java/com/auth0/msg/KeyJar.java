
package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.TypeError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Assert;
import org.slf4j.LoggerFactory;

import javax.rmi.CORBA.Util;
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

    public List<KeyBundle> getBundle(String owner) {
        return  issuerKeys.get(owner);
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

        List<Key> keyListToReturn = new ArrayList<>();
        for(KeyBundle keyBundle : keyBundleList) {
            List<Key> tempKeyList1 = new ArrayList<>();
            if(!Utils.isNullOrEmpty(keyType)) {
                tempKeyList1 = keyBundle.get(keyType);
            } else {
                tempKeyList1 = keyBundle.getKeys();
            }

            for(Key key : tempKeyList1) {
                if(key.getInactiveSince() != 0 && !"sig".equals(keyUse)) {
                    continue;
                }
                if(Utils.isNullOrEmpty(key.getUse()) || use.equals(key.getUse())) {
                    if(!Utils.isNullOrEmpty(kid))  {
                        if(kid.equals(key.getKid())) {
                            keyListToReturn.add(key);
                            break;
                        } else
                            continue;
                    } else {
                        keyListToReturn.add(key);
                    }
                }
            }
        }

        // if elliptic curve have to check I have a key of the right curve
        if("EC".equals(keyType) && args.containsKey("alg")) {
            String name = "P-" + args.get("alg").substring(2);
            List<Key> tempKeyList2 = new ArrayList<>();
            List<Key> keyList = new ArrayList<>();
            for(Key key : keyListToReturn) {
                if(key instanceof ECKey) {
                    ECKey ecKey = (ECKey) key;
                    if (!name.equals(ecKey.getCrv()))
                        continue;
                    else
                        tempKeyList2.add(key);
                }
            }
            keyListToReturn = tempKeyList2;
        }

        if("enc".equals(use) && "oct".equals(keyType) && !Utils.isNullOrEmpty(owner)) {
            for(KeyBundle keyBundle : this.issuerKeys.get("")) {
                for(Key key : keyBundle.get(keyType)) {
                    if(key.getInactiveSince() != 0)
                        continue;
                    if(Utils.isNullOrEmpty(key.getUse())  || use.equals(key.getUse())) {
                        keyListToReturn.add(key);
                    }
                }
            }
        }

        return keyListToReturn;
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

    public void loadKeys(Map<String,Object> pcr, String issuer, boolean shouldReplace) throws ImportException, KeyException {
        logger.debug("loading keys for issuer: " + issuer);

        if(shouldReplace || !this.issuerKeys.keySet().contains(issuer)) {
            this.issuerKeys.put(issuer, new ArrayList<KeyBundle>());
        }
        String jwksUri = (String) pcr.get("jwks_uri");
        if(!Utils.isNullOrEmpty(jwksUri)) {
            addUrl(issuer, jwksUri, null);

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
                    List<Map<String, Object>> k2 = (List<Map<String, Object>>)jwks.get("keys");
                    addKeyBundle(issuer, new KeyBundle(k2, "", 0, verifySSL, "jwk", "", null));
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

        if(!Utils.isNullOrEmpty(kid)) {
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

    public List<java.security.Key> getJWTVerifyKeys(String jwtString, String issuer, Map<String, List<String>> noKidIssuers, boolean allowMissingKid, boolean trustJKU) {
        DecodedJWT jwt = JWT.decode(jwtString);
        String alg = jwt.getAlgorithm();
        String keyType = alg2KeyType(alg);
        String kid = Utils.isNullOrEmpty(jwt.getKeyId()) ? "" : jwt.getKeyId();
        Map<String, List<String>> nki = null;
        if(noKidIssuers == null)
            nki = new HashMap<>();
        else
            nki = noKidIssuers;
        List<Key> keys = getKeys("sig", keyType, "", "", null);
        String iss = Utils.isNullOrEmpty(jwt.getIssuer()) ? issuer : jwt.getIssuer();
        if(!Utils.isNullOrEmpty(iss)) {
            addKey(keys, iss, "sig", keyType, kid, nki, allowMissingKid);
        }
        // First extend the keyjar if allowed
        String jku = jwt.getHeaderClaim("jku").asString();
        if(!Utils.isNullOrEmpty(jku) && !Utils.isNullOrEmpty(iss)) {
            if(find(jku, iss) == null) {
                if(trustJKU) {
                    try {
                        addUrl(iss, jku, null);
                    } catch(ImportException | KeyException e) {

                    }
                }
            }
        }

        String[] claimsList = new String[] {"aud", "client_id"};
        for(String claim : claimsList) {
            Claim payloadClaim = jwt.getClaim(claim);
            if(payloadClaim == null)
                continue;
            if(claim.equals("aud")) {
                List<String> audList = null;
                if(payloadClaim.asString() != null) {
                    audList = new ArrayList<>();
                    audList.add(payloadClaim.asString());
                } else if(payloadClaim.asList(String.class) != null) {
                    audList = payloadClaim.asList(String.class);
                }
                if(audList != null) {
                    for(String aud: audList) {
                        addKey(keys, aud, "sig", keyType, kid, nki, allowMissingKid);
                    }
               }
            } else {
                keys = addKey(keys, payloadClaim.asString(), "sig", keyType, kid, nki, allowMissingKid);
            }
        }

        // Only want the public keys. Symmetric keys are also OK.
        List<java.security.Key> returnKeys = new ArrayList<>();
        for(Key key : keys) {
            if(key.isPublicKey()) {
                try {
                    returnKeys.add(key.getKey(false));
                } catch(ValueError e) {
                }
            }
        }
        return returnKeys;
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

    public static KeyJar buildKeyJar(List<Object> keyConf, String kidTemplate, KeyJar keyJar, Map<String, Object> kidd) {
        try {
            if(keyJar == null )
                keyJar = new KeyJar();

            if(kidd == null) {
                kidd = new HashMap<>();
                kidd.put("sig", new HashMap<>());
                kidd.put("enc", new HashMap<>());
            }

            int kid = 0;
            Map<String, Object> jwks = new HashMap<>();
            List<Object> keysList = new ArrayList<>();
            jwks.put("keys", new ArrayList());

            for(Object specConf : keyConf) {
                Map<String, Object>  spec = (Map<String,Object>) specConf;
                String type = spec.get("type") != null ? ((String)spec.get("type")).toUpperCase() : "";
                KeyBundle kb = new KeyBundle();
                if(type.equals("RSA")) {
                    if(spec.get("key") != null) {
                        try {
                            kb = new KeyBundle(null, "file://" + (String) spec.get("key"), 0, true, "der", type, (List<String>) spec.get("use"));
                        } catch(Exception e) {

                        }
                    } else {
                        kb = KeyBundle.rsaInit(spec);
                    }
                } else if(type.equals("EC")) {
                    kb = KeyBundle.ecInit(spec);
                }
                if(kb != null) {
                    for(Key key : kb.getKeys()) {
                        if(!Utils.isNullOrEmpty(kidTemplate)) {
                            key.setKid(String.format(kidTemplate, kid++));
                        } else {
                            key.addKid();
                        }
                        Map<String, Object> usage = (Map<String, Object> )kidd.get(key.getUse());
                        if(usage == null) {
                            usage = new HashMap<>();
                        }
                        usage.put(key.getKty(), key.getKid());
                        kidd.put(key.getUse(), usage);
                    }

                    for(Key k : kb.getKeys()) {
                        if(!k.getKty().equals("oct")) {
                            try {
                                keysList.add(k.serialize());
                            }catch(SerializationNotPossible e) {

                            }
                        }
                    }
                    jwks.put("keys", keysList);
                    keyJar.addKeyBundle("", kb);
                    System.out.println(jwks.toString());
                    System.out.println(kidd.toString());
                }
            }
        } catch (ImportException e) {

        }

        // Python returns jwks, keyjar, kidd
        return keyJar;
    }

    public static KeyJar initKeyJar(String publicPath, String privatePath, String keyDefs, String issuer) {
        // TODO

        return null;
    }

    private String alg2KeyType(String alg) {
        if(Utils.isNullOrEmpty(alg) || alg.toLowerCase().equals("none")) {
            return "none";
        } else if(alg.startsWith("RS") || alg.startsWith("PS")) {
            return "RSA";
        } else if(alg.startsWith("HS") || alg.startsWith("A")) {
            return "oct";
        } else if(alg.startsWith("ES") || alg.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return "";
        }
    }
}

