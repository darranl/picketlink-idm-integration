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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.jboss.sasl.callback.DigestHashCallback;
import org.jboss.sasl.callback.VerifyPasswordCallback;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Credentials.Status;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.credential.UsernamePasswordCredentials;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.query.RelationshipQuery;

/**
 * A CallbackHandler that can delegate to a PicketLink {@link IdentityManager}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PicketLinkCallbackHandler implements CallbackHandler {

    private final IdentityManager identityManager;

    public PicketLinkCallbackHandler(final IdentityManager identityManager) {
        this.identityManager = identityManager;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        List<Callback> toRespondTo = new ArrayList<Callback>(1);

        String username = null;

        for (Callback current : callbacks) {
            if (current instanceof NameCallback) {
                username = ((NameCallback) current).getDefaultName();
            } else if (current instanceof VerifyPasswordCallback) {
                toRespondTo.add(current);
            } else if (current instanceof DigestHashCallback) {
                toRespondTo.add(current);
            } else if (current instanceof AuthorizeCallback) {
                toRespondTo.add(current);
            } else if (current instanceof RealmCallback) {
                // TODO - Add support for this as we could choose a realm.
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }

        for (Callback current : toRespondTo) {
            if (current instanceof VerifyPasswordCallback) {
                if (username == null) {
                    throw new IOException("Attempt to verify password with no user specified.");
                }

                VerifyPasswordCallback vpc = (VerifyPasswordCallback) current;
                Password password = new Password(vpc.getPassword());
                UsernamePasswordCredentials upc = new UsernamePasswordCredentials(username, password);

                identityManager.validateCredentials(upc);
                // Don't need to go into any more detail, it is either valid or it is not.
                vpc.setVerified(upc.getStatus() == Status.VALID);
            } else if (current instanceof AuthorizeCallback) {
                AuthorizeCallback acb = (AuthorizeCallback) current;
                acb.setAuthorized(authorizedAs(acb.getAuthenticationID(), acb.getAuthorizationID()));
            } else {
                throw new UnsupportedCallbackException(current, current.getClass().getSimpleName() + " not supported.");
            }
        }
    }

    private boolean authorizedAs(final String authenticationId, final String requestedAuthorization) {
        if (authenticationId.equals(requestedAuthorization)) {
            // Assuming all users are allowed to run as themselves.
            return true;
        }

        IdentityType authenticatedIdentity = identityManager.getAgent(authenticationId);
        IdentityType authorizationIdentity = identityManager.getAgent(requestedAuthorization);

        if (authenticatedIdentity == null || authorizationIdentity == null) {
            /*
             * If authenticatedIdentity was not found by this point there would be a bigger problem but for the purpose of this
             * check if either do not exist then the authorization can not be granted anyway.
             */
            return false;
        }

        RelationshipQuery<RunAsRelationship> query = identityManager.createRelationshipQuery(RunAsRelationship.class);

        query.setParameter(RunAsRelationship.AUTHENTICATED_IDENTITY, authenticatedIdentity);
        query.setParameter(RunAsRelationship.AUTHORIZED_AS, authorizationIdentity);

        List<RunAsRelationship> result = query.getResultList();

        if (result.size() == 0) {
            return false;
        } else if (result.size() == 1) {
            return true;
        }

        throw new IllegalStateException("An unexpected number of relationship mappings were returned.");
    }

}
