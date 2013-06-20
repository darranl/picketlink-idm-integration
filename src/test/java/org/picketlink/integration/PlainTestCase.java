/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.picketlink.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

import org.junit.Test;

/**
 * Test class to test that Plain SASL mechanism against the single {@link IdentityManager} definition.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PlainTestCase extends AbstractTestBase {

    private static final String PLAIN = "PLAIN";

    /**
     * Test a successful authentication using the plain mechanism.
     */
    @Test
    public void successfulAuth() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Jack", "Jack_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Jack", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("Jack", server.getAuthorizationID());
    }

    @Test
    public void badPassword() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Jack", "Olivia_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Jack", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        try {
            server.evaluateResponse(message);
            fail("Expected exception not thrown.");
        } catch (IOException expected) {
        }

        assertFalse(server.isComplete());
    }

    @Test
    public void badUserName() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Jackson", "Jack_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Jack", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        try {
            server.evaluateResponse(message);
            fail("Expected exception not thrown.");
        } catch (IOException expected) {
        }

        assertFalse(server.isComplete());
    }

    @Test
    public void successfulAuthorization() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Oliver", "Oliver_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Harry", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("Harry", server.getAuthorizationID());
    }

    @Test
    public void failedAuthorization() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Harry", "Harry_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Oliver", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        try {
            server.evaluateResponse(message);
            fail("Expected exception not thrown.");
        } catch (IOException expected) {
        }

        assertFalse(server.isComplete());
    }

    @Test
    public void successfulAuthorization_SophieAsEmily() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Sophie", "Sophie_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Emily", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("Emily", server.getAuthorizationID());
    }

    @Test
    public void successfulAuthorization_EmilyAsSophie() throws Exception {
        CallbackHandler serverCallback = new PicketLinkCallbackHandler(getIdentityManager());
        SaslServer server = Sasl.createSaslServer(PLAIN, "TestProtocol", "TestServer", Collections.<String, Object> emptyMap(),
                serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("Emily", "Emily_Password".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[] { PLAIN }, "Sophie", "TestProtocol", "TestServer",
                Collections.<String, Object> emptyMap(), clientCallback);

        assertTrue(client.hasInitialResponse());
        byte[] message = client.evaluateChallenge(new byte[0]);

        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("Sophie", server.getAuthorizationID());
    }

}
