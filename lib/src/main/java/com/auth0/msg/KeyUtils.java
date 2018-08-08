package com.auth0.msg;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;



public class KeyUtils {

    private static byte[] parsePEMFile(File pemFile) throws IOException {
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.",
                pemFile.getAbsolutePath()));
        }
        PemReader reader = new PemReader(new FileReader(pemFile));
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    private static PublicKey getRSAPublicKey(byte[] keyBytes, String algorithm) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidKeySpecException e) {
        }
        return publicKey;
    }

    private static PrivateKey getRSAPrivateKey(byte[] keyBytes, String algorithm) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
        } catch (InvalidKeySpecException e) {
        }

        return privateKey;
    }

    /**
     * Get a PublicKey from a PEM public key file
     * @param filepath filename path
     * @return PublicKey The public key
     * @throws IOException
     */
    public static PublicKey readRSAPublicKeyFromFile(String filepath)
        throws IOException {
        byte[] bytes = KeyUtils.parsePEMFile(new File(filepath));
        return KeyUtils.getRSAPublicKey(bytes, "RSA");
    }

    /**
     * Get a private key from the PEM private key file
     * @param filepath filename path
     * @return PrivateKey The private key
     * @throws IOException
     */
    public static PrivateKey readRSAPrivateKeyFromFile(String filepath)
        throws IOException {
        byte[] bytes = KeyUtils.parsePEMFile(new File(filepath));
        return KeyUtils.getRSAPrivateKey(bytes, "RSA");
    }

    /**
     * Get a public/private key from the PEM encoded file
     * @param filepath filename of the private/public key file
     * @return Key a private or private key
     * @throws IOException
     */
    public static java.security.Key readRSAKeyFromFile(String filepath)
        throws IOException {
        byte[] bytes = KeyUtils.parsePEMFile(new File(filepath));

        java.security.Key key = KeyUtils.getRSAPublicKey(bytes, "RSA");
        if(key == null) {
            key = KeyUtils.getRSAPrivateKey(bytes, "RSA");
        }
        return key;
    }

    /**
     * Writes the RSA key as PEM encode file
     * @param filepath output filename
     * @param key The private or public RSA key
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void writeRSAPemFile(String filepath, java.security.Key key)
        throws FileNotFoundException , IOException{
        String type = null;
        if(key instanceof PublicKey) {
            type = "RSA PUBLIC KEY";
        } else if(key instanceof  PrivateKey) {
            type = "RSA PRIVATE KEY";
        }
        PemWriter pemWriter =
            new PemWriter((new OutputStreamWriter(new FileOutputStream(filepath))));
        try {
            PemObject pemObject = new PemObject(type, key.getEncoded());
            pemWriter.writeObject(pemObject);
        }finally {
            pemWriter.close();
        }
    }


//    public void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
//        PrivateKey privateKey = keyPair.getPrivate();
//        PublicKey publicKey = keyPair.getPublic();
//
//        //unencrypted form of PKCS#8 file
//        JcaPKCS8Generator gen1 = new JcaPKCS8Generator(keyPair.getPrivate(), null);
//        PemObject obj1 = gen1.generate();
//        StringWriter sw1 = new StringWriter();
//        try (JcaPEMWriter pw = new JcaPEMWriter(sw1)) {
//            pw.writeObject(obj1);
//        }
//        String pkcs8Key1 = sw1.toString();
//        FileOutputStream fos1 = new FileOutputStream("D:\\privatekey-unencrypted.pkcs8");
//        fos1.write(pkcs8Key1.getBytes());
//        fos1.flush();
//        fos1.close();
//
//        // Store Public Key.
//        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
//            publicKey.getEncoded());
//        FileOutputStream fos = new FileOutputStream(path + "/public.key");
//        fos.write(x509EncodedKeySpec.getEncoded());
//        fos.close();
//
//        // Store Private Key.
//        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
//            privateKey.getEncoded());
//        fos = new FileOutputStream(path + "/private.key");
//        fos.write(pkcs8EncodedKeySpec.getEncoded());
//        fos.close();
//    }
}
