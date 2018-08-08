package com.auth0.msg;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class ECKeyTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testGenECKey() {
        String curves[] = new String[]{"P-256", "P-384", "P-521"};
        for(String curve : curves) {
            KeyPair keyPair = ECKey.generateECKeyPair(curve);
            Assert.assertNotNull(keyPair);
            Assert.assertTrue(keyPair.getPrivate() instanceof ECPrivateKey);
            Assert.assertTrue(keyPair.getPublic() instanceof ECPublicKey);
        }
    }


}
