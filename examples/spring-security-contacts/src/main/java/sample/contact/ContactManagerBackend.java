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
package sample.contact;

import org.springframework.security.Authentication;

import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.MutableAclService;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.userdetails.UserDetails;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.support.ApplicationObjectSupport;

import org.springframework.util.Assert;

import java.util.List;
import java.util.Random;


/**
 * Concrete implementation of {@link ContactManager}.
 *
 * @author Ben Alex
 * @version $Id: ContactManagerBackend.java 974 2009-01-14 00:39:45Z sgonzalez $
 */
public class ContactManagerBackend extends ApplicationObjectSupport implements ContactManager, InitializingBean {
    //~ Instance fields ================================================================================================

    private ContactDao contactDao;
    private MutableAclService mutableAclService;
    private int counter = 1000;

    //~ Methods ========================================================================================================

    public void addPermission(Contact contact, Sid recipient, Permission permission) {
        MutableAcl acl;
        ObjectIdentity oid = new ObjectIdentityImpl(Contact.class, contact.getId());

        try {
            acl = (MutableAcl) mutableAclService.readAclById(oid);
        } catch (NotFoundException nfe) {
            acl = mutableAclService.createAcl(oid);
        }

        acl.insertAce(acl.getEntries().length, permission, recipient, true);
        mutableAclService.updateAcl(acl);

        if (logger.isDebugEnabled()) {
            logger.debug("Added permission " + permission + " for Sid " + recipient + " contact " + contact);
        }
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(contactDao, "contactDao required");
        Assert.notNull(mutableAclService, "mutableAclService required");
    }

    public void create(Contact contact) {
        // Create the Contact itself
        contact.setId(new Long(counter++));
        contactDao.create(contact);

        // Grant the current principal administrative permission to the contact
        addPermission(contact, new PrincipalSid(getUsername()), BasePermission.ADMINISTRATION);

        if (logger.isDebugEnabled()) {
            logger.debug("Created contact " + contact + " and granted admin permission to recipient " + getUsername());
        }
    }

    public void delete(Contact contact) {
        contactDao.delete(contact.getId());

        // Delete the ACL information as well
        ObjectIdentity oid = new ObjectIdentityImpl(Contact.class, contact.getId());
        mutableAclService.deleteAcl(oid, false);

        if (logger.isDebugEnabled()) {
            logger.debug("Deleted contact " + contact + " including ACL permissions");
        }
    }

    public void deletePermission(Contact contact, Sid recipient, Permission permission) {
        ObjectIdentity oid = new ObjectIdentityImpl(Contact.class, contact.getId());
        MutableAcl acl = (MutableAcl) mutableAclService.readAclById(oid);

        // Remove all permissions associated with this particular recipient (string equality to KISS)
        AccessControlEntry[] entries = acl.getEntries();

        for (int i = 0; i < entries.length; i++) {
            if (entries[i].getSid().equals(recipient) && entries[i].getPermission().equals(permission)) {
                acl.deleteAce(i);
            }
        }

        mutableAclService.updateAcl(acl);

        if (logger.isDebugEnabled()) {
            logger.debug("Deleted contact " + contact + " ACL permissions for recipient " + recipient);
        }
    }

    public List getAll() {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning all contacts");
        }

        return contactDao.findAll();
    }

    public List getAllRecipients() {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning all recipients");
        }

        List list = contactDao.findAllPrincipals();

        return list;
    }

    public Contact getById(Long id) {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning contact with id: " + id);
        }

        return contactDao.getById(id);
    }

    /**
     * This is a public method.
     *
     * @return DOCUMENT ME!
     */
    public Contact getRandomContact() {
        if (logger.isDebugEnabled()) {
            logger.debug("Returning random contact");
        }

        Random rnd = new Random();
        List contacts = contactDao.findAll();
        int getNumber = rnd.nextInt(contacts.size());

        return (Contact) contacts.get(getNumber);
    }

    protected String getUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            return auth.getPrincipal().toString();
        }
    }

    public void setContactDao(ContactDao contactDao) {
        this.contactDao = contactDao;
    }

    public void setMutableAclService(MutableAclService mutableAclService) {
        this.mutableAclService = mutableAclService;
    }

    public void update(Contact contact) {
        contactDao.update(contact);

        if (logger.isDebugEnabled()) {
            logger.debug("Updated contact " + contact);
        }
    }
}
