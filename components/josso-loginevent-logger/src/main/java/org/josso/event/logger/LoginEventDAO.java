/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.josso.event.logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.josso.gateway.event.exceptions.SSOEventException;

/**
 *
 * @author leohol
 */
public class LoginEventDAO {

    private Connection _conn;
    private String _loginEventDML;
    private static final Log logger = LogFactory.getLog(LoginEventDAO.class);

    public LoginEventDAO(Connection _connection, String _loginEventDML) {
        this._conn = _connection;
        this._loginEventDML = _loginEventDML;
    }

    public void logLoginEvent(String username, String ssoSessionId, String remoteHost)
            throws SSOEventException {
        PreparedStatement stmt = null;
        try {
            if (logger.isDebugEnabled()) {
                logger.debug("log loginEvent user:" + username + ", ssoSessionId: " + ssoSessionId + ", remotehost: " + remoteHost);
            }

            stmt = createPreparedStatement(_loginEventDML);
            stmt.setString(1, username);
            stmt.setString(2, ssoSessionId);
            stmt.setString(3, remoteHost);
            stmt.execute();
            _conn.commit();

        } catch (SQLException e) {
            logger.error("SQLException while logging login event ", e);
            throw new SSOEventException("During logging login event: " + e.getMessage());
        } finally {
            closeStatement(stmt);
        }
    }

    private PreparedStatement createPreparedStatement(String query)
            throws SQLException {

        if (logger.isDebugEnabled()) {
            logger.debug("[createPreparedStatement()] : " + "(" + query + ")");
        }

        PreparedStatement stmt =
                _conn.prepareStatement(query + " ");

        return stmt;
    }

    protected void closeStatement(PreparedStatement stmt)
            throws SSOEventException {
        try {
            if (stmt != null) {
                stmt.close();
            }
        } catch (SQLException se) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error clossing statement");
            }

            throw new SSOEventException("Error while clossing statement: \n " + se.getMessage());

        } catch (Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error clossing statement");
            }

            // throw new SSOIdentityException("Error while clossing statement: \n " + e.getMessage());
        }
    }
}
