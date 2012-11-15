/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.josso.event.logger;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.josso.gateway.event.SSOEvent;
import org.josso.gateway.event.SSOEventListener;
import org.josso.gateway.event.security.SSOIdentityEvent;
import org.josso.gateway.event.exceptions.SSOEventException;

/**
 *
 * @author leohol
 * @org.apache.xbean.XBean element="loginevent-logger"
 */
public class LoginEventLogger implements SSOEventListener {

    private static final Log logger = LogFactory.getLog(LoginEventLogger.class);
    private String _dsJndiName;
    private DataSource _datasource;
    private String _loginEventDML;

    public String getName() {
        return "org.josso.event.logger.LoginEventLogger";
    }

    public void handleSSOEvent(SSOEvent event) {
        if (logger.isDebugEnabled()) {
            logger.debug("event " + event.getType() + " fired");
        }

        if (event.getType().equals("authenticationSuccess")) {
            Connection c = null;
            try {
                SSOIdentityEvent identityEvent = (SSOIdentityEvent) event;

                if (logger.isDebugEnabled()) {
                    logger.debug("loginevent logged for user" + identityEvent.getUsername());
                }


                c = getDBConnection();
                LoginEventDAO loginEventDAO = new LoginEventDAO(c, _loginEventDML);
                loginEventDAO.logLoginEvent(identityEvent.getUsername(), identityEvent.getSessionId(), identityEvent.getRemoteHost());
                System.out.println("-- event erkannt ");
            } catch (SSOEventException ex) {
                logger.error("Error during catch of login event ", ex);
            } finally {
                try {
                    close(c);
                } catch (SSOEventException ex) {
                    logger.error(null, ex);
                }
            }
        }
    }

    public void setDsJndiName(String _dsJndiName) {
        this._dsJndiName = _dsJndiName;
        this._datasource = null;
    }

    public void setLoginEventDML(String _loginEventDML) {
        this._loginEventDML = _loginEventDML;
    }

    protected DataSource getDataSource() throws SSOEventException {

        if (_datasource == null) {

            try {

                if (logger.isDebugEnabled()) {
                    logger.debug("[getDatasource() : ]" + _dsJndiName);
                }

                InitialContext ic = new InitialContext();
                Context envCtx = (Context) ic.lookup("java:comp/env");
                _datasource = (DataSource) envCtx.lookup(_dsJndiName);

            } catch (NamingException ne) {
                logger.error("Error during DB connection lookup", ne);
                throw new SSOEventException(
                        "Error During Lookup\n" + ne.getMessage());
            }

        }

        return _datasource;
    }

    private Connection getDBConnection() throws SSOEventException {
        try {
            return getDataSource().getConnection();
        } catch (SQLException e) {
            logger.error("[getDBConnection()]:" + e.getErrorCode() + "/" + e.getSQLState() + "]" + e.getMessage());
            throw new SSOEventException(
                    "Exception while getting connection: \n " + e.getMessage());
        }
    }

    private void close(Connection dbConnection) throws SSOEventException {
        try {
            if (dbConnection != null
                    && !dbConnection.isClosed()) {
                dbConnection.close();
            }
        } catch (SQLException se) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error while clossing connection");
            }

            throw new SSOEventException("Error while clossing connection\n" + se.getMessage());
        } catch (Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error while clossing connection");
            }

            throw new SSOEventException("Error while clossing connection\n" + e.getMessage());
        }

    }
}
