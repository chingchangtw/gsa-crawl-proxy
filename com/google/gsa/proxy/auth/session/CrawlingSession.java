 /**
  * Copyright (C) 2008 Google - Enterprise EMEA SE
  *
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy of
  * the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  * License for the specific language governing permissions and limitations under
  * the License.
  */


package com.google.gsa.proxy.auth.session;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credentials;
import com.google.gsa.proxy.auth.CrawlingUtils;
import com.google.gsa.sessions.Sessions;
import com.google.gsa.sessions.UserIDEncoder;
import com.google.gsa.sessions.UserSession;

import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveConfigurationException;

import java.io.UnsupportedEncodingException;

import java.net.URLEncoder;

import java.util.Date;
import java.util.Vector;

import javax.servlet.http.Cookie;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;


/**
 * This class manages all the session when crawling. It stores a session whenever
 * a new crawl request is coming from the appliance and no previous session exists,
 * or the existing session has reached the timeout. The session timeout is 
 * configured in the crawl config file.
 * The whole Crawl Proxy security lifecycle resides in this class that implements
 * methods used by the other classes in this application when it's needed to set 
 * ot get something to/from the session.
 * 
 * 
 */
public class CrawlingSession {

    //Logger
    private static Logger logger = Logger.getLogger(CrawlingSession.class);

    //Timeout in minutes
    private static long timeout = -1; //default value is -1 (no timeout)

    //Session instance: singleton
    private static Sessions sessions = null;

    //Authentication class name
    private static String authenticationProcessClsName = null;

    //Valve Configuration instance
    private ValveConfiguration valveConf = null;

    //Time
    private static final long MILLS_IN_SEC = 1000;
    private static final long SEC_IN_MIN = 60;

    //Encoding
    private static String encoder = "UTF-8";


    /**
     * Class constructor
     * It creates the session instance if it does not exist
     */
    public CrawlingSession() {
        if (sessions == null) {
            sessions = Sessions.getInstance();
        }
    }

    /**
     * Class constructor
     * It creates the session instance if it does not exist. Sets the timeout 
     * that is passed to the method.
     * 
     * @param timeout number of minutes the session is going to be active
     */
    public CrawlingSession(long timeout) {
        if (sessions == null) {
            this.timeout = timeout;
            sessions = Sessions.getInstance();
        }
    }

    /**
     * Sets the valve configuration instance (if not already set)
     * 
     * @param valveConf unique ValveConfiguration instance
     */
    public void setValveConf(ValveConfiguration valveConf) {
        if (this.valveConf == null) {
            this.valveConf = valveConf;
        }
    }

    /**
     * Creates a new user session and adds it with the other sessions
     * 
     * @param sessionID session identifier
     * @param userSession the user session instance to be added
     */
    private void createSession(String sessionID, UserSession userSession) {
        if (sessions != null) {
            sessions.addSession(sessionID, userSession);
        }
    }

    /**
     * Removes an existing session from the session vector
     * 
     * @param sessionID session identifier
     */
    private void deleteSession(String sessionID) {
        if (sessions != null) {
            sessions.deleteSession(sessionID);
        }
    }

    /**
     * Returns a session (if it already exists)
     * 
     * @param sessionID session identifier
     * 
     * @return the user session
     */
    public UserSession getSession(String sessionID) {

        UserSession userSession = null;

        if (sessions != null) {

            userSession = sessions.getUserSession(sessionID);

            if (userSession == null) {
                logger.debug("User session was not found");
            } else {
                logger.debug("User session found");
            }
        } else {
            logger.debug("Sessions vector is null");
        }
        return userSession;
    }

    /**
     * Checks if a user session already exists
     * 
     * @param sessionID session identifier
     * 
     * @return if the user session exists or not
     */
    public boolean doesSessionExist(String sessionID) {

        boolean sessionExist = false;

        if (sessions != null) {
            sessionExist = sessions.doesSessionExist(sessionID);
        }
        return sessionExist;
    }

    /**
     * It authenticates the user the first time against the root authentication 
     * process defined in the configuration files. Manages the sessions as well accordingly.
     * Returns the result of the authentication process as a standard HTTP 
     * error code
     * 
     * @param sessionID sesion identifier
     * @param userName user login
     * @param request HTTP request coming from the GSA
     * @param response HTTP response that is going to be sent back to the GSA
     * @param authCookies cookies created during the authentication process
     * @param url url requested
     * @param creds crawler credentials
     * @param id credential id that is going to be used as the main authn credentials
     * 
     * @return the HTTP error code as a result of the authentication process
     */
    public int authenticate(String sessionID, String userName, 
                            HttpServletRequest request, 
                            HttpServletResponse response, 
                            Vector<Cookie> authCookies, String url, 
                            Credentials creds, String id) {

        int authnResponse = HttpServletResponse.SC_UNAUTHORIZED;

        logger.debug("Authenticate method");

        //Use a Valve internal URL
        String internalURL = valveConf.getTestFormsCrawlUrl();
        if ((internalURL == null) || (internalURL.equals(""))) {
            internalURL = url;
        }

        //only allow once process in the authenticate method
        synchronized (sessions) {

            try {
                //protection: just in case more than one thread enters in this method
                if (doesSessionExist(sessionID)) {
                    logger.debug("The session is now OK. Returning with SC_OK");
                    return HttpServletResponse.SC_OK;
                }
                //authentication
                logger.debug("Authenticate crawler");

                //Authentication process
                AuthenticationProcessImpl authenticationProcessCls;
                try {
                    authenticationProcessCls = setAuthenticationProcessImpl();
                } catch (ValveConfigurationException e) {
                    logger.error("Valve configuration error: " + 
                                 e.getMessage(), e);
                    authnResponse = 
                            HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                    return authnResponse;
                }

                if (authenticationProcessCls != null) {
                    authnResponse = 
                            authenticationProcessCls.authenticate(request, 
                                                                  response, 
                                                                  authCookies, 
                                                                  internalURL, 
                                                                  creds, id);
                }

                if (authnResponse == HttpServletResponse.SC_OK) {
                    //create session
                    logger.debug("Authentication process has been OK. Let's create the session");
                    long sessionCreationTime = System.currentTimeMillis();
                    //Create authn cookie
                    Cookie authnCookie = createAuthNCookie(sessionID);
                    //add authn cookie into the cookie vector
                    if (authnCookie != null) {
                        CrawlingUtils.addCookie(authCookies, authnCookie);
                    }
                    //Prepare cookies to be included in the session
                    Cookie[] cookies = 
                        CrawlingUtils.transformCookiesToArray(authCookies);
                    UserSession userSession = 
                        createUserSession(userName, sessionCreationTime, creds, 
                                          cookies);
                    createSession(sessionID, userSession);
                    logger.debug("Session created");
                }

            } catch (Exception e) {
                logger.error("Crawl Authentication error: " + e);
            }
        }

        return authnResponse;

    }


    /**
     * It's equivalent to authenticate() method. It authenticates the 
     * crawler user once an already existing session is in place although
     * it's no longer valid.
     * 
     * @param sessionID sesion identifier
     * @param userName user login
     * @param request HTTP request coming from the GSA
     * @param response HTTP response that is going to be sent back to the GSA
     * @param authCookies cookies created during the authentication process
     * @param url url requested
     * @param creds crawler credentials
     * @param id credential id that is going to be used as the main authn credentials
     * 
     * @return the HTTP error code as a result of the authentication process
     */
    public int reauthenticate(String sessionID, String userName, 
                              HttpServletRequest request, 
                              HttpServletResponse response, 
                              Vector<Cookie> authCookies, String url, 
                              Credentials creds, String id) {

        int authnResponse = HttpServletResponse.SC_UNAUTHORIZED;

        logger.debug("Reauthenticate method");

        //Use a Valve internal URL
        String internalURL = valveConf.getTestFormsCrawlUrl();
        if ((internalURL == null) || (internalURL.equals(""))) {
            internalURL = url;
        }

        //only allow once process in the authenticate method
        synchronized (sessions) {

            try {
                //protection: just in case more than one thread enters in this method                 
                if (isValidSession(sessionID)) {
                    logger.debug("The session is now OK. Returning with SC_OK");
                    return HttpServletResponse.SC_OK;
                }

                //delete session                 
                if (doesSessionExist(sessionID)) {
                    logger.debug("Deleting invalid session");
                    deleteSession(sessionID);
                }

                //reauthentication
                logger.debug("Reauthenticate crawler");

                //Authentication process
                AuthenticationProcessImpl authenticationProcessCls;
                try {
                    authenticationProcessCls = setAuthenticationProcessImpl();
                } catch (ValveConfigurationException e) {
                    logger.error("Valve configuration error: " + 
                                 e.getMessage(), e);
                    authnResponse = 
                            HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
                    return authnResponse;
                }

                if (authenticationProcessCls != null) {
                    authnResponse = 
                            authenticationProcessCls.authenticate(request, 
                                                                  response, 
                                                                  authCookies, 
                                                                  internalURL, 
                                                                  creds, id);
                }

                if (authnResponse == HttpServletResponse.SC_OK) {
                    logger.debug("Authentication process has been OK. Let's create the session");
                    long sessionCreationTime = System.currentTimeMillis();
                    //Create authn cookie
                    Cookie authnCookie = createAuthNCookie(sessionID);
                    //add authn cookie into the cookie vector
                    if (authnCookie != null) {
                        CrawlingUtils.addCookie(authCookies, authnCookie);
                    }
                    //Prepare cookies to be included in the session
                    Cookie[] cookies = 
                        CrawlingUtils.transformCookiesToArray(authCookies);
                    //Create session
                    UserSession userSession = 
                        createUserSession(userName, sessionCreationTime, creds, 
                                          cookies);
                    createSession(sessionID, userSession);
                    logger.debug("Session created");
                }

            } catch (Exception e) {
                logger.error("Crawl Authentication error: " + e);
            }
        }

        return authnResponse;

    }

    /**
     * It creates the authentication cookie created as a result of a 
     * succesful authentication process.
     * 
     * @param sessionID the session identifier
     * 
     * @return the authentication cookie
     */
    private Cookie createAuthNCookie(String sessionID) {

        Cookie authCookie = null;

        //Encoding sessionID
        String encodedSessionID = null;
        try {
            encodedSessionID = URLEncoder.encode(sessionID, encoder);
        } catch (UnsupportedEncodingException e) {
            logger.error("Error during session encoding: " + e.getMessage(), 
                         e);
            encodedSessionID = sessionID;
        }

        //read parameters from config file
        String authCookieName = null;
        String authCookieDomain = null;
        String authCookiePath = null;
        int authMaxAge = -1;
        try {
            authCookieName = valveConf.getAuthCookieName();
            authCookieDomain = valveConf.getAuthCookieDomain();
            authCookiePath = valveConf.getAuthCookiePath();
            authMaxAge = new Integer(valveConf.getAuthMaxAge()).intValue();
        } catch (Exception e) {
            logger.error("Error when reading cookie parameters. Check auth* params in Valve config file");
            return null;
        }

        authCookie = new Cookie(authCookieName, encodedSessionID);

        // Set cookie domain
        authCookie.setDomain(authCookieDomain);

        // Set cookie path
        authCookie.setPath(authCookiePath);

        // Set expiration time
        authCookie.setMaxAge(authMaxAge);

        return authCookie;
    }


    /**
     * Checks if the session is still valid
     * 
     * @param sessionID session identifier
     * 
     * @return if the session is still valid or not
     */
    public boolean isValidSession(String sessionID) {

        boolean validSession = false;
        UserSession userSession = null;

        try {

            if (sessions != null) {
                userSession = sessions.getInstance().getUserSession(sessionID);
                if (userSession != null) {
                    logger.debug("User Session exists");
                    if (userSession.getValidSession()) {
                        if (timeout < 0) {
                            //if timeout is less than 0, the session is valid
                            validSession = true;
                        } else {
                            //check if it's still a valid session
                            validSession = sessionValidity(userSession);
                            logger.debug("Checking session validity: " + 
                                         validSession);
                        }
                    }
                } else {
                    logger.debug("User Session does NOT exist");
                }
            }

        } catch (Exception e) {
            logger.error("Error during session validation: " + e);
        }

        return validSession;

    }

    /**
     * Checks if the entire user session that it's passed to this method 
     * is still valid based on the creation time and the session timeout
     * 
     * @param userSession user session to be checked
     * 
     * @return if the session is still valid or not
     */
    private boolean sessionValidity(UserSession userSession) {

        boolean sessionValidity = false;

        try {

            if (userSession != null) {
                long creationTime = userSession.getSessionCreationTime();
                long currentTime = System.currentTimeMillis();
                long timeoutMills = timeout * SEC_IN_MIN * MILLS_IN_SEC;
                long validityTime = creationTime + timeoutMills;
                if (validityTime >= currentTime) {
                    sessionValidity = true;
                }

            } else {
                logger.debug("User Session is null");
            }

        } catch (Exception e) {
            logger.error("Error when checking if session is valid based on timeout: " + 
                         e);
        }

        return sessionValidity;

    }

    /**
     * Creates a new user session instance with the information passed
     * 
     * @param userName user login
     * @param sessionCreationTime long var that holds the session creation time
     * @param userCredentials user credential container
     * @param cookies authentication cookies created during the login process
     * 
     * @return the user session created for this method
     */
    public UserSession createUserSession(String userName, 
                                         long sessionCreationTime, 
                                         Credentials userCredentials, 
                                         Cookie[] cookies) {

        UserSession userSession = null;

        try {
            userSession = 
                    new UserSession(userName, sessionCreationTime, userCredentials, 
                                    cookies);
        } catch (Exception ex) {
            logger.error("Error during the instatiation of the User Session: " + 
                         ex);
        } finally {
        }

        return userSession;
    }

    /**
     * Sets the authentication process that is declared in the configuration
     * files. This class will drive the authentication process and it's usually 
     * rootAuthenticationProcess class.
     * 
     * @return the authentication process
     * 
     * @throws ValveConfigurationException
     */
    public AuthenticationProcessImpl setAuthenticationProcessImpl() throws ValveConfigurationException {

        AuthenticationProcessImpl authenticationProcessImpl = null;

        //Set authenticationProcessClsName if it has not been done yet
        if (authenticationProcessClsName == null) {
            //read the authorization class name from Valve Config
            if (valveConf != null) {
                authenticationProcessClsName = 
                        valveConf.getAuthenticationProcessImpl();
                logger.debug("Setting authenticationProcessClsName: " + 
                             authenticationProcessClsName);
            } else {
                // Throw Configuration Exception
                throw new ValveConfigurationException("Valve Configuration file has not been set correctly");
            }

        }

        // Protection
        if ((authenticationProcessClsName == null) || 
            (authenticationProcessClsName.equals(""))) {

            // Throw Configuration Exception
            throw new ValveConfigurationException("Configuration parameter [authorizationProcessImpl] has not been set correctly");

        }

        try {

            // Instantiate the authorization process class                 
            authenticationProcessImpl = 
                    (AuthenticationProcessImpl)Class.forName(authenticationProcessClsName).newInstance();
            authenticationProcessImpl.setValveConfiguration(valveConf);

        } catch (InstantiationException ie) {

            // Throw Configuration Exception
            throw new ValveConfigurationException("Configuration parameter [authorizationProcessImpl] has not been set correctly - InstantiationException");


        } catch (IllegalAccessException iae) {

            // Throw Configuration Exception
            throw new ValveConfigurationException("Configuration parameter [authorizationProcessImpl] has not been set correctly - IllegalAccessException");

        } catch (ClassNotFoundException cnfe) {

            // Throw Configuration Exception
            throw new ValveConfigurationException("Configuration parameter [authorizationProcessImpl] has not been set correctly - ClassNotFoundException");

        }

        return authenticationProcessImpl;

    }

}
