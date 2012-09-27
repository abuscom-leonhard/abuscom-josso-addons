/*
 * JOSSO: Java Open Single Sign-On
 *
 * Copyright 2004-2009, Atricore, Inc.
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
 *
 */
package org.josso.gateway.identity.service.store.multipleldap;

import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.josso.auth.BindableCredentialStore;
import org.josso.auth.exceptions.AuthenticationFailureException;
import org.josso.auth.exceptions.SSOAuthenticationException;

import javax.naming.AuthenticationException;
import javax.naming.ldap.InitialLdapContext;
import org.josso.auth.Credential;
import org.josso.auth.CredentialKey;
import org.josso.auth.CredentialProvider;
import org.josso.gateway.identity.exceptions.NoSuchUserException;
import org.josso.gateway.identity.exceptions.SSOIdentityException;
import org.josso.gateway.identity.service.BaseRole;
import org.josso.gateway.identity.service.BaseUser;
import org.josso.gateway.identity.service.store.AbstractStore;
import org.josso.gateway.identity.service.store.ExtendedIdentityStore;
import org.josso.gateway.identity.service.store.UserKey;
import org.josso.gateway.identity.service.store.ldap.LDAPBindIdentityStore;
import org.josso.selfservices.ChallengeResponseCredential;

/**
 * An implementation of an Identity and Credential Store which obtains credential, user and role information from an LDAP server using JNDI,
 * based on the configuration properties.
 * <p/>
 * It allows to set whatever options your LDAP JNDI provider supports your Gateway configuration file. Examples of standard property names
 * are: <ul> <li><code>initialContextFactory = "java.naming.factory.initial"</code> <li><code>securityProtocol = "java.naming.security.protocol"</code> <li><code>providerUrl = "java.naming.provider.url"</code> <li><code>securityAuthentication = "java.naming.security.authentication"</code>
 * </ul>
 * <p/>
 * This store implementation is both an Identity Store and Credential Store. Since in JOSSO the authentication of the user is left to the
 * configured Authentication Scheme, this store implementation cannot delegate user identity assertion by binding to the LDAP server. For
 * that reason it retrieves the required credentials from the directory leaving the authentication procedure to the configured
 * Authentication Scheme. The store must be supplied with the configuratoin parameters so that it can retrieve user identity information.
 * <p/>
 * <
 * p/>
 * Additional component properties include: <ul> <li>securityPrincipal: the DN of the user to be used to bind to the LDAP Server
 * <li>securityCredential: the securityPrincipal password to be used for binding to the LDAP Server. <li>securityAuthentication: the
 * security level to be used with the LDAP Server session. Its value is one of the following strings: "none", "simple", "strong". If not
 * set, "simple" will be used. <li>usersCtxDN : the fixed distinguished name to the context to search for user accounts.
 * <li>principalUidAttributeID: the name of the attribute that contains the user login name. This is used to locate the user. <li>rolesCtxDN
 * : The fixed distinguished name to the context to search for user roles. <li>uidAttributeID: the name of the attribute that, in the object
 * containing the user roles, references role members. The attribute value should be the DN of the user associated with the role. This is
 * used to locate the user roles. <li>roleAttributeID : The name of the attribute that contains the role name <li>credentialQueryString :
 * The query string to obtain user credentials. It should have the following format : user_attribute_name=credential_attribute_name,... For
 * example : uid=username,userPassword=password <li>userPropertiesQueryString : The query string to obtain user properties. It should have
 * the following format : ldap_attribute_name=user_attribute_name,... For example : mail=mail,cn=description </ul> A sample LDAP Identity
 * Store configuration :
 * <p/>
 * <
 * pre>
 * &lt;sso-identity-store&gt;
 * &lt;class&gt;org.josso.gateway.identity.service.store.ldap.LDAPBindIdentityStore&lt;/class&gt;
 * &lt;initialContextFactory&gt;com.sun.jndi.ldap.LdapCtxFactory&lt;/initialContextFactory&gt;
 * &lt;providerUrl&gt;ldap://localhost&lt;/providerUrl&gt;
 * &lt;securityPrincipal&gt;cn=Manager\,dc=my-domain\,dc=com&lt;/securityPrincipal&gt;
 * &lt;securityCredential&gt;secret&lt;/securityCredential&gt;
 * &lt;securityAuthentication&gt;simple&lt;/securityAuthentication&gt;
 * &lt;usersCtxDN&gt;ou=People\,dc=my-domain\,dc=com&lt;/usersCtxDN&gt;
 * &lt;principalUidAttributeID&gt;uid&lt;/principalUidAttributeID&gt;
 * &lt;rolesCtxDN&gt;ou=Roles\,dc=my-domain\,dc=com&lt;/rolesCtxDN&gt;
 * &lt;uidAttributeID&gt;uniquemember&lt;/uidAttributeID&gt;
 * &lt;roleAttributeID&gt;cn&lt;/roleAttributeID&gt;
 * &lt;credentialQueryString&gt;uid=username\,userPassword=password&lt;/credentialQueryString&gt;
 * &lt;userPropertiesQueryString&gt;mail=mail\,cn=description&lt;/userPropertiesQueryString&gt;
 * &lt;/sso-identity-store&gt;
 * </pre>
 * <p/>
 * A sample LDAP Credential Store configuration :
 * <p/>
 * <
 * pre>
 * &lt;credential-store&gt;
 * &lt;class&gt;org.josso.gateway.identity.service.store.ldap.LDAPBindIdentityStore&lt;/class&gt;
 * &lt;initialContextFactory&gt;com.sun.jndi.ldap.LdapCtxFactory&lt;/initialContextFactory&gt;
 * &lt;providerUrl&gt;ldap://localhost&lt;/providerUrl&gt;
 * &lt;securityPrincipal&gt;cn=Manager\,dc=my-domain\,dc=com&lt;/securityPrincipal&gt;
 * &lt;securityCredential&gt;secret&lt;/securityCredential&gt;
 * &lt;securityAuthentication&gt;simple&lt;/securityAuthentication&gt;
 * &lt;usersCtxDN&gt;ou=People\,dc=my-domain\,dc=com&lt;/usersCtxDN&gt;
 * &lt;principalUidAttributeID&gt;uid&lt;/principalUidAttributeID&gt;
 * &lt;rolesCtxDN&gt;ou=Roles\,dc=my-domain\,dc=com&lt;/rolesCtxDN&gt;
 * &lt;uidAttributeID&gt;uniquemember&lt;/uidAttributeID&gt;
 * &lt;roleAttributeID&gt;cn&lt;/roleAttributeID&gt;
 * &lt;credentialQueryString&gt;uid=username\,userPassword=password&lt;/credentialQueryString&gt;
 * &lt;userPropertiesQueryString&gt;mail=mail\,cn=description&lt;/userPropertiesQueryString&gt;
 * &lt;/credential-store&gt;
 * </pre>
 *
 * @org.apache.xbean.XBean element="mldap-bind-store"
 *
 * @author <a href="mailto:gbrigand@josso.org">Gianluca Brigandi</a>
 * @version CVS $Id: LDAPBindIdentityStore.java 543 2008-03-18 21:34:58Z sgonzalez $
 */
public class MultipleLDAPBindIdentityStore extends AbstractStore implements BindableCredentialStore {

    private static final Log logger = LogFactory.getLog(MultipleLDAPBindIdentityStore.class);
    private List<LDAPBindIdentityStore> credentialStores;

    public List<LDAPBindIdentityStore> getCredentialStores() {
        return credentialStores;
    }

    public void setCredentialStores(List<LDAPBindIdentityStore> credentialStores) {
        this.credentialStores = credentialStores;
    }

    public BaseUser loadUser(UserKey key) throws NoSuchUserException, SSOIdentityException {
        for (LDAPBindIdentityStore credentialStore : credentialStores) {
            try {
                return credentialStore.loadUser(key);
            } catch (Exception e) {
                logger.info("Could not load user in store");
            }
        }
        throw new SSOIdentityException("could not load user in any store");
    }

    public BaseRole[] findRolesByUserKey(UserKey key) throws SSOIdentityException {
        for (LDAPBindIdentityStore credentialStore : credentialStores) {
            try {
                return credentialStore.findRolesByUserKey(key);
            } catch (Exception e) {
                logger.info("Could not load roles in store");
            }
        }
        throw new SSOIdentityException("could not load roles in any store");
    }

    public Credential[] loadCredentials(CredentialKey key, CredentialProvider cp) throws SSOIdentityException {
        for (LDAPBindIdentityStore credentialStore : credentialStores) {
            try {
                return credentialStore.loadCredentials(key, cp);
            } catch (Exception e) {
                logger.info("Could not load credential in store");
            }
        }
        throw new SSOIdentityException("could not load credential in any store");
    }

    public String loadUID(CredentialKey key, CredentialProvider cp) throws SSOIdentityException {
        for (LDAPBindIdentityStore credentialStore : credentialStores) {
            try {
                return credentialStore.loadUID(key, cp);
            } catch (Exception e) {
                logger.info("Could not load uid in store");
            }
        }
        throw new SSOIdentityException("could not load uid in any store");
    }

    public boolean bind(String username, String password) throws SSOAuthenticationException {
        for (LDAPBindIdentityStore credentialStore : credentialStores) {
            try {
                boolean result = credentialStore.bind(username, password);
                if (result) return true;
            } catch (Exception e) {
                logger.info("Could not bind user in store");
            }
        }
        throw new SSOAuthenticationException("could not authenticate user in any store");
    }


}
