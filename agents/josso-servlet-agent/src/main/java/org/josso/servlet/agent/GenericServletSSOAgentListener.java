package org.josso.servlet.agent;

import org.josso.agent.LocalSession;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;
import java.util.Map;

/**
 * @author <a href=mailto:sgonzalez@atricore.org>Sebastian Gonzalez Oyuela</a>
 */
public class GenericServletSSOAgentListener implements HttpSessionListener {

    public void sessionCreated(HttpSessionEvent httpSessionEvent) {

    }

    public void sessionDestroyed(HttpSessionEvent httpSessionEvent) {
        Map sessionMap = (Map) httpSessionEvent.getSession().getServletContext().getAttribute(GenericServletSSOAgentFilter.KEY_SESSION_MAP);
        if (sessionMap == null)
            return;

        LocalSession localSession = (LocalSession) sessionMap.remove(httpSessionEvent.getSession().getId());
        if (localSession != null)
            localSession.expire();
    }
}