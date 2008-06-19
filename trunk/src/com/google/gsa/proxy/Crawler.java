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

package com.google.gsa.proxy;

import com.google.gsa.AuthorizationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;

import com.google.gsa.proxy.auth.session.CrawlingSession;

import com.google.gsa.proxy.auth.CrawlingUtils;
import com.google.gsa.proxy.auth.ipaddress.IPAddressChecker;
import com.google.gsa.proxy.auth.ipaddress.IPAddresses;
import com.google.gsa.proxy.config.Config;
import com.google.gsa.sessions.UserSession;

import com.google.gsa.sessions.nonValidSessionException;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveConfigurationException;

import com.google.gsa.valve.configuration.ValveConfigurationInstance;

import com.google.gsa.valve.modules.utils.AuthorizationUtils;

import java.io.IOException;

import java.util.Vector;

import javax.naming.NamingException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.log4j.Logger;

/**
 * This is the class that implements the main crawl process, serving content 
 * from the remote repositories back to the appliance. It acts as a proxy that 
 * can be used in the middle between the search appliance and the remote 
 * content sources. 
 * <p>
 * It's implemented as a Java filter that gets the crawl requests and validate if 
 * they are OK and sends back to the appliance the result of accessing the 
 * remote document. It uses some security rules like IP address restriction.
 * 
 */
public class Crawler implements Filter {

    private FilterConfig _filterConfig = null;

    //Logger
    private Logger logger = Logger.getLogger(Crawler.class);

    //Basic
    private static final String HEADER_BASIC = "Basic";

    //HTTP Request and Response objects
    private HttpServletRequest httpRequest = null;
    private HttpServletResponse httpResponse = null;

    //Crawling Session instance
    private static CrawlingSession crawlSession = null;

    //Authorization Process
    private static String authorizationProcessClsName = null;

    //Valve Configuration instance
    private ValveConfiguration valveConf = null;

    //Configuration file pointers
    private static String gsaValveConfigPath = null;
    private static String crawlerConfigPath = null;


    /**
     * Init method
     * 
     * @param filterConfig filter config
     * 
     * @throws ServletException
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        _filterConfig = filterConfig;
    }


    /**
     * Destroy method
     */
    public void destroy() {
        _filterConfig = null;
    }


    /**
     * This is the main method of the Filter invoked by the Java application 
     * whenever the request matches with the rules configured at web.xml file.
     * It checks the response is OK and then processes the request sending back 
     * the result to the appliance (crawler).
     * 
     * @param request servlet HTTP request
     * @param response servlet HTTP response
     * @param chain servlet chain
     * 
     * @throws IOException
     * @throws ServletException
     */
    public void doFilter(ServletRequest request, ServletResponse response, 
                         FilterChain chain) throws IOException, 
                                                   ServletException {

        int responseCode = HttpServletResponse.SC_UNAUTHORIZED;

        //Translate Request and Response objects                
        try {
            httpRequest = (HttpServletRequest)request;
            httpResponse = (HttpServletResponse)response;
        } catch (Exception ex) {
            logger.error("Error when class casting Request and Response: " + 
                         ex.getMessage(), ex);
        } finally {
        }

        //Process request
        try {
            //Set Config file paths
            setConfigFilePaths();

            //Set Valve config
            initializeValveConfiguration();

            //Execute doProcess
            responseCode = doProcess(httpRequest, httpResponse);
        } catch (Exception e) {
            logger.error("Error doing crawling process: " + e.getMessage(), e);
            responseCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        //Set error
        httpResponse.setStatus(responseCode);
    }

    /**
     * Processes the http request and responds with the authn/authz result
     * 
     * @param httpRequest servlet HTTP request
     * @param httpResponse servlet HTTP response
     * 
     * @return the HTTP error code
     * 
     * @throws IOException
     */
    public int doProcess(HttpServletRequest httpRequest, 
                         HttpServletResponse httpResponse) throws IOException {

        //doProcess variable initialization
        String realm = null; //Domain realm
        String timeout = null; //SAML timeout       
        String url = null; //URL coming in the request
        String credID = null; //Credential ID

        logger.debug("Starting doProcess");

        //Get realm and check it's OK
        try {
            realm = 
                    Config.getConfig(crawlerConfigPath).getString(".crawler.realm");
        } catch (ConfigurationException e) {
            logger.error("Error when reading realm: " + e.getMessage(), e);
        }
        if (realm == null) {
            logger.error("Realm could not be read from the config file");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        //Check if the request contains the HTTP Basic credentials. If not, send back the unauthorized error with the WWW-Authenticate header                      
        if (!CrawlingUtils.doesContainBasicHeader(httpRequest)) {
            logger.debug("The request does not contain Basic credentials");
            CrawlingUtils.sendAuthenticateHeader(httpResponse, realm);
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        //Check if it is the Crawler user. If not, send back unauthorized error
        if (!CrawlingUtils.isCrawler(httpRequest)) {
            logger.warn("The user is not crawler");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        //Reading the valid IP Addresses from the config file
        IPAddressChecker ipAddressChecker = null;
        try {
            ipAddressChecker = CrawlingUtils.getIPAddresses();
        } catch (Exception e) {
            logger.error("Error when getting IP Addresses: " + e.getMessage(), 
                         e);
        }
        //Check if the sender is in between the IP Addresses
        String remoteAddress = httpRequest.getRemoteAddr();
        logger.debug("The remote address is: " + remoteAddress);
        IPAddresses sourceIPAddress = new IPAddresses(remoteAddress);

        if (!ipAddressChecker.isIPAddressIncluded(sourceIPAddress)) {
            logger.warn("The remote IP Address is not included in the permitted list");
            return HttpServletResponse.SC_UNAUTHORIZED;
        }

        //Set the 
        String authZHeader = CrawlingUtils.getAuthorizationHeader(httpRequest);
        //This is the credential string and Session ID as well
        String credStr = authZHeader.substring(HEADER_BASIC.length());

        //Get timeout (maxSessionAge) and check it's OK        
        try {
            timeout = Config.getConfig().getString(".session.maxSessionAge");
        } catch (ConfigurationException e) {
            logger.error("Error when reading timeout: " + e.getMessage(), e);
        }
        if (timeout == null) {
            logger.error("Session Timeout could not be read from the config file");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        //Get URL
        //url = httpRequest.getRequestURL().toString();
        url = getUrl(httpRequest);
        logger.debug("URL is: " + url);

        //Get CredID        
        try {
            credID = Config.getConfig().getString(".crawler.credentialID");
        } catch (ConfigurationException e) {
            logger.error("Error when reading Credential ID: " + e.getMessage(), 
                         e);
        }
        if (credID == null) {
            logger.error("Credential ID could not be read from the config file");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        Vector<Cookie> authCookies = new Vector<Cookie>();

        //Credentials
        Credential cred = 
            CrawlingUtils.getBasicCredentials(authZHeader, realm, credID);

        //Protection: check credentials have the right format 
        if (cred == null) {
            logger.error("Basic Credentials does not have the correct format");
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        //Add credentials
        Credentials creds = new Credentials();
        creds.add(cred);

        //Session status: set default value
        int resultCode = HttpServletResponse.SC_UNAUTHORIZED;

        //Instantiate Crawling session        
        crawlSession = new CrawlingSession(new Long(timeout).longValue());
        //Set Valve Config
        crawlSession.setValveConf(valveConf);

        //Get session
        logger.debug("Session ID to be seeked: " + credStr);
        UserSession userSession = crawlSession.getSession(credStr);

        //Check if session exists. If not, create/recreate it
        if (userSession == null) {

            resultCode = 
                    crawlSession.authenticate(credStr, cred.getUsername(), httpRequest, 
                                              httpResponse, authCookies, url, 
                                              creds, credID);

            //Check resultCode
            if (resultCode != HttpServletResponse.SC_OK) {
                logger.error("Authentication result is not OK: " + resultCode);
                return resultCode;
            } else {
                userSession = crawlSession.getSession(credStr);
            }

        } else {

            //Check the session is valid
            if (!crawlSession.isValidSession(credStr)) {
                //reauthenticate
                resultCode = 
                        crawlSession.reauthenticate(credStr, cred.getUsername(), 
                                                    httpRequest, httpResponse, 
                                                    authCookies, url, creds, 
                                                    credID);

                //Check resultCode
                if (resultCode != HttpServletResponse.SC_OK) {
                    logger.error("Authentication result is not OK: " + 
                                 resultCode);
                    return resultCode;
                } else {
                    userSession = crawlSession.getSession(credStr);
                }

            }
        }

        //Authorization
        AuthorizationProcessImpl authorizationProcessCls;
        try {
            authorizationProcessCls = setAuthorizationProcessImpl();
        } catch (ValveConfigurationException e) {
            logger.error("Valve configuration error: " + e.getMessage(), e);
            resultCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            return resultCode;
        }

        if (authorizationProcessCls != null) {

            //Avoid HTML processing (URL rewriting)
            AuthorizationUtils.setProcessHTML(false);

            try {
                logger.debug("Authorization process [" + url + "]");
                //
                //Launch authorization process                
                resultCode = 
                        authorizationProcessCls.authorize(httpRequest, httpResponse, 
                                                          userSession.getCookies(), 
                                                          url, credID);
                //Check if result is -1 (there is no pattern in the config file that matches with the URL)
                if (resultCode == -1) {
                    logger.debug("Auth pattern not found for such URL. Setting 401");
                    resultCode = HttpServletResponse.SC_UNAUTHORIZED;
                }

            } catch (nonValidSessionException e) {
                logger.error("Session is not longer valid: " + e.getMessage(), 
                             e);
                resultCode = HttpServletResponse.SC_UNAUTHORIZED;
            }
        } else {
            logger.error("Authorization class is NULL");
            resultCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }

        logger.debug("Response status is: " + resultCode);

        return resultCode;
    }

    /**
     * Sets the authorization class that drives the authorization 
     * process
     * 
     * @return the name of the class that drives the authorization process
     * 
     * @throws ValveConfigurationException
     */
    public AuthorizationProcessImpl setAuthorizationProcessImpl() throws ValveConfigurationException {

        AuthorizationProcessImpl authorizationProcessImpl = null;

        //Set authorizationProcessClsName if it has not been done yet
        if (authorizationProcessClsName == null) {
            //read the authorization class name from Valve Config
            if (valveConf != null) {
                authorizationProcessClsName = 
                        valveConf.getAuthorizationProcessImpl();
                logger.debug("Setting authorizationProcessClsName: " + 
                             authorizationProcessClsName);
            } else {
                // Throw Configuration Exception
                throw new ValveConfigurationException("Valve Configuration file has not been set correctly");
            }

        }

        // Protection
        if ((authorizationProcessClsName == null) || 
            (authorizationProcessClsName.equals(""))) {

            // Throw Configuration Exception
            throw new ValveConfigurationException("Configuration parameter [authorizationProcessImpl] has not been set correctly");

        }

        try {

            // Instantiate the authorization process class

            authorizationProcessImpl = 
                    (AuthorizationProcessImpl)Class.forName(authorizationProcessClsName).newInstance();
            authorizationProcessImpl.setValveConfiguration(valveConf);

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

        return authorizationProcessImpl;

    }


    /**
     * Sets the config file location (if they were not set yet)
     * 
     */
    private void setConfigFilePaths() {

        //Only process if either Valve or Crawler config file paths are not set yet
        if ((gsaValveConfigPath == null) || (crawlerConfigPath == null)) {

            //Get Context vars
            javax.naming.Context ctx = null;
            javax.naming.Context env = null;
            try {
                ctx = new javax.naming.InitialContext();
                env = (javax.naming.Context)ctx.lookup("java:comp/env");
            } catch (NamingException e) {
                logger.error("Error when setting the Naming Context (Config paths): " + 
                             e.getMessage(), e);
            }


            //If Valve config file path is null: read the pointer from environment (web.xml)
            if (gsaValveConfigPath == null) {
                try {
                    //Set gsaValveConfigPath
                    gsaValveConfigPath = 
                            (String)env.lookup("gsaValveConfigPath");
                } catch (NamingException e) {
                    logger.error("Error when setting Valve config path: " + 
                                 e.getMessage(), e);
                }

                logger.debug("gsaValveConfigPath is: " + gsaValveConfigPath);
            }

            //If Crawler config file path is null: read the pointer from environment (web.xml)
            if (crawlerConfigPath == null) {
                try {
                    //Set crawlerConfigPath
                    crawlerConfigPath = 
                            (String)env.lookup("crawlerConfigPath");
                } catch (NamingException e) {
                    logger.error("Error when setting Crawler config path: " + 
                                 e.getMessage(), e);
                }

                logger.debug("crawlerConfigPath is: " + crawlerConfigPath);
            }

        }
    }

    /**
     * Sets the ValveConf instance from the config file. 
     * It only processes it if this var has not been set yet
     * 
     */
    private void initializeValveConfiguration() {
        //Initialize valveConf only if it was not set yet
        if (valveConf == null) {
            //Check if the pointer is already defined
            if (gsaValveConfigPath != null) {
                try {
                    valveConf = 
                            ValveConfigurationInstance.getValveConfig(gsaValveConfigPath);
                } catch (ValveConfigurationException e) {
                    logger.error("Error when setting Valve configuration instance: " + 
                                 e.getMessage(), e);
                }
            } else {
                logger.error("The Valve config path is not readable. Check web.xml to set it properly");
            }
        }
    }

    /**
     * Gets the complete URL that is being requested by the crawler
     * 
     * @param request servlet HTTP request
     * 
     * @return the complete URL
     */
    public static String getUrl(HttpServletRequest request) {
        String reqUrl = request.getRequestURL().toString();
        String queryString = request.getQueryString();
        if (queryString != null) {
            reqUrl += "?" + queryString;
        }
        return reqUrl;
    }


}
