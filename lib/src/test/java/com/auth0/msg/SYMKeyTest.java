package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class SYMKeyTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testGetKey() throws Exception, SerializationNotPossible {
        SYMKey symKey = new SYMKey("",
            Base64.encodeBase64URLSafeString("mekmitasdigoat".getBytes("UTF-8")));
        Assert.assertNotNull(symKey.getKey(false));
        Assert.assertNotNull(symKey.getKey(true));

    }

    @Test
    public void testDeserialize() throws Exception {
        exception.expect(DeserializationNotPossible.class);
        SYMKey symKey = new SYMKey("", (Key) null);
    }

    @Test
    public void testDeserialize2() throws Exception {
        exception.expect(DeserializationNotPossible.class);
        SYMKey symKey = new SYMKey(null, null, null, null, null, null, null, null, null);
    }

}
