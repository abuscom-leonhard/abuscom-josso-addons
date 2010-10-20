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

import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AclService;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import org.springframework.web.bind.RequestUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Controller for "administer" index page.
 *
 * @author Ben Alex
 * @version $Id: AdminPermissionController.java 974 2009-01-14 00:39:45Z sgonzalez $
 */
public class AdminPermissionController implements Controller, InitializingBean {
    //~ Instance fields ================================================================================================

    private AclService aclService;
    private ContactManager contactManager;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(contactManager, "A ContactManager implementation is required");
        Assert.notNull(aclService, "An aclService implementation is required");
    }

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        int id = RequestUtils.getRequiredIntParameter(request, "contactId");

        Contact contact = contactManager.getById(new Long(id));
        Acl acl = aclService.readAclById(new ObjectIdentityImpl(contact));

        Map model = new HashMap();
        model.put("contact", contact);
        model.put("acl", acl);

        return new ModelAndView("adminPermission", "model", model);
    }

    public void setAclService(AclService aclService) {
        this.aclService = aclService;
    }

    public void setContactManager(ContactManager contact) {
        this.contactManager = contact;
    }
}
