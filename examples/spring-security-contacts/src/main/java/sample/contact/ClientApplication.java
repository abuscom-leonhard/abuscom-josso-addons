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

import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.beans.factory.ListableBeanFactory;

import org.springframework.context.support.FileSystemXmlApplicationContext;

import org.springframework.util.StopWatch;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import java.util.Iterator;
import java.util.List;
import java.util.Map;


/**
 * Demonstrates accessing the {@link ContactManager} via remoting protocols.<P>Based on Spring's JPetStore sample,
 * written by Juergen Hoeller.</p>
 *
 * @author Ben Alex
 */
public class ClientApplication {
    //~ Instance fields ================================================================================================

    private final ListableBeanFactory beanFactory;

    //~ Constructors ===================================================================================================

    public ClientApplication(ListableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    //~ Methods ========================================================================================================

    public void invokeContactManager(Authentication authentication, int nrOfCalls) {
        StopWatch stopWatch = new StopWatch(nrOfCalls + " ContactManager call(s)");
        Map contactServices = this.beanFactory.getBeansOfType(ContactManager.class, true, true);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        for (Iterator it = contactServices.keySet().iterator(); it.hasNext();) {
            String beanName = (String) it.next();

            Object object = this.beanFactory.getBean("&" + beanName);

            try {
                System.out.println("Trying to find setUsername(String) method on: " + object.getClass().getName());

                Method method = object.getClass().getMethod("setUsername", new Class[] {String.class});
                System.out.println("Found; Trying to setUsername(String) to " + authentication.getPrincipal());
                method.invoke(object, new Object[] {authentication.getPrincipal()});
            } catch (NoSuchMethodException ignored) {
                System.out.println("This client proxy factory does not have a setUsername(String) method");
            } catch (IllegalAccessException ignored) {
                ignored.printStackTrace();
            } catch (InvocationTargetException ignored) {
                ignored.printStackTrace();
            }

            try {
                System.out.println("Trying to find setPassword(String) method on: " + object.getClass().getName());

                Method method = object.getClass().getMethod("setPassword", new Class[] {String.class});
                method.invoke(object, new Object[] {authentication.getCredentials()});
                System.out.println("Found; Trying to setPassword(String) to " + authentication.getCredentials());
            } catch (NoSuchMethodException ignored) {
                System.out.println("This client proxy factory does not have a setPassword(String) method");
            } catch (IllegalAccessException ignored) {}
            catch (InvocationTargetException ignored) {}

            ContactManager remoteContactManager = (ContactManager) contactServices.get(beanName);
            System.out.println("Calling ContactManager '" + beanName + "'");

            stopWatch.start(beanName);

            List contacts = null;

            for (int i = 0; i < nrOfCalls; i++) {
                contacts = remoteContactManager.getAll();
            }

            stopWatch.stop();

            if (contacts.size() != 0) {
                Iterator listIterator = contacts.iterator();

                while (listIterator.hasNext()) {
                    Contact contact = (Contact) listIterator.next();
                    System.out.println("Contact: " + contact.toString());
                }
            } else {
                System.out.println("No contacts found which this user has permission to");
            }

            System.out.println();
            System.out.println(stopWatch.prettyPrint());
        }

        SecurityContextHolder.clearContext();
    }

    public static void main(String[] args) {
        String username = System.getProperty("username", "");
        String password = System.getProperty("password", "");
        String nrOfCallsString = System.getProperty("nrOfCalls", "");

        if ("".equals(username) || "".equals(password)) {
            System.out.println(
                "You need to specify the user ID to use, the password to use, and optionally a number of calls "
                + "using the username, password, and nrOfCalls system properties respectively. eg for user rod, "
                + "use: -Dusername=rod -Dpassword=koala' for a single call per service and "
                + "use: -Dusername=rod -Dpassword=koala -DnrOfCalls=10 for ten calls per service.");
            System.exit(-1);
        } else {
            int nrOfCalls = 1;

            if (!"".equals(nrOfCallsString)) {
                nrOfCalls = Integer.parseInt(nrOfCallsString);
            }

            ListableBeanFactory beanFactory = new FileSystemXmlApplicationContext("clientContext.xml");
            ClientApplication client = new ClientApplication(beanFactory);

            client.invokeContactManager(new UsernamePasswordAuthenticationToken(username, password), nrOfCalls);
            System.exit(0);
        }
    }
}
