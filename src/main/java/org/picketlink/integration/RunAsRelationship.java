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

import org.picketlink.idm.model.AbstractAttributedType;
import org.picketlink.idm.model.Agent;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.model.Relationship;
import org.picketlink.idm.model.annotation.IdentityProperty;
import org.picketlink.idm.query.RelationshipQueryParameter;

/**
 * A {@link Relationship} to model which {@link Agent}s can run as which {@link Agents}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class RunAsRelationship extends AbstractAttributedType implements Relationship {

    private static final long serialVersionUID = -6030130476332002734L;

    public static final RelationshipQueryParameter AUTHENTICATED_IDENTITY = new RelationshipQueryParameter() {

        public String getName() {
            return "authenticatedIdentity";
        }
    };;

    public static final RelationshipQueryParameter AUTHORIZED_AS = new RelationshipQueryParameter() {

        public String getName() {
            return "authorizedAs";
        }
    };;

    private IdentityType authenticatedIdentity;

    private IdentityType authorizedAs;

    @IdentityProperty
    public IdentityType getAuthenticatedIdentity() {
        return authenticatedIdentity;
    }

    public void setAuthenticatedIdentity(IdentityType authenticatedIdentity) {
        this.authenticatedIdentity = authenticatedIdentity;
    }

    @IdentityProperty
    public IdentityType getAuthorizedAs() {
        return authorizedAs;
    }

    public void setAuthorizedAs(IdentityType authorizedAs) {
        this.authorizedAs = authorizedAs;
    }

}
