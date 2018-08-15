package com.auth0.msg;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * Utility functions for reading/writing PEM encode files
 *
 */
public class KeyUtils {

    /**
     * Parses a PEM encoded file and returns the key contents
     * @param pemFile
     * @return key contents without wrappers
     * @throws IOException
     */
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

    /**
     * Get RSA public key from encoded bytes
     * @param keyBytes encoded key bytes
     * @param algorithm algorithm for key (RSA)
     * @return the RSA public key instance
     */
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

    /**
     * Get the RSA private key from encoded bytes
     * @param keyBytes encoded key bytes
     * @param algorithm algorithm for the key (RSA)
     * @return the RSA private key instance
     */
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
    public static PublicKey getRSAPublicKeyFromFile(String filepath)
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
    public static PrivateKey getRSAPrivateKeyFromFile(String filepath)
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
    public static java.security.Key getRSAKeyFromFile(String filepath)
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

    /**
     * Gets the RSA public key from a X.509 certificate file
     * @param pemFile X.509 certificate file
     * @return RSA public key
     * @throws IOException
     * @throws CertificateException
     */
    public static java.security.PublicKey getRSAKeyFromCertFile(String pemFile) throws IOException, CertificateException {
        byte[] bytes = KeyUtils.parsePEMFile(new File(pemFile));
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(
            new ByteArrayInputStream(bytes));
        return certificate.getPublicKey();
    }

}
