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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;

import org.jboss.sasl.JBossSaslProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.config.IdentityConfigurationBuilder;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.internal.IdentityManagerFactory;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.model.Realm;
import org.picketlink.idm.model.SimpleUser;

/**
 * The base class for tests sharing a common {@link IdentityManager}
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class AbstractTestBase {

    private static final Provider jbossSaslProvider = new JBossSaslProvider();
    private static IdentityManager identityManager;

    @BeforeClass
    public static void registerProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            public Integer run() {
                return Security.insertProviderAt(jbossSaslProvider, 1);
            }
        });
    }

    @AfterClass
    public static void removeProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(jbossSaslProvider.getName());

                return null;
            }
        });
    }

    @BeforeClass
    public static void initialise() {
        System.out.println("initialise");
        IdentityConfigurationBuilder builder = new IdentityConfigurationBuilder();

        builder.stores().file().preserveState(false).addRealm("ManagementRealm").supportAllFeatures().supportRelationshipType(RunAsRelationship.class);

        IdentityManagerFactory factory = new IdentityManagerFactory(builder.build());
        identityManager = factory.createIdentityManager(new Realm("ManagementRealm"));

        addUser("Jack", "Jack_Password");
        String oliverId = addUser("Oliver", "Oliver_Password");
        String harryId = addUser("Harry", "Harry_Password");
        addUser("Charlie", "Charlie_Password");
        addUser("Alfie", "Alfie_Password");
        addUser("Olivia", "Olivia_Password");
        addUser("Ruby", "Ruby_Password");
        addUser("Lily", "Lily_Password");
        String sophieId = addUser("Sophie", "Sophie_Password");
        String emilyId = addUser("Emily", "Emily_Password");

        addRunAsPermission(oliverId, harryId);
        addRunAsPermission(sophieId, emilyId);
        addRunAsPermission(emilyId, sophieId);
    }

    protected static String addUser(final String loginName, final String password) {
        SimpleUser user = new SimpleUser(loginName);
        identityManager.add(user);

        Password pwd = new Password(password.toCharArray());
        identityManager.updateCredential(user, pwd);

        return user.getId();
    }

    protected static void addRunAsPermission(final String authenticatedAgent, final String authorizedAs) {
        RunAsRelationship relationship = new RunAsRelationship();
        IdentityType authenticated = identityManager.lookupIdentityById(IdentityType.class, authenticatedAgent);
        IdentityType authorized = identityManager.lookupIdentityById(IdentityType.class, authorizedAs);
        relationship.setAuthenticatedIdentity(authenticated);
        relationship.setAuthorizedAs(authorized);

        identityManager.add(relationship);
    }

    @AfterClass
    public static void tearDown() {
        identityManager = null;
    }

    protected IdentityManager getIdentityManager() {
        return identityManager;
    }

}
