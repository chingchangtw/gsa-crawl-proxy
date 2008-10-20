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

package com.google.gsa.proxy.auth;

import com.google.gsa.Credential;

import com.google.gsa.proxy.auth.ipaddress.IPAddressChecker;
import com.google.gsa.proxy.auth.ipaddress.IPAddresses;
import com.google.gsa.proxy.config.Config;

import java.util.Vector;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

/**
 * It contains several useful static methods that are used by some of the 
 * classes included in this crawl framework.
 * The methods included in this class process different aspects like the 
 * HTTP Basic authentication headers or the cookie management.
 * 
 */
public class CrawlingUtils {


    //Logger
    private static Logger logger = Logger.getLogger(CrawlingUtils.class);

    //Authentication Headers
    private static final String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String HEADER_BASIC = "Basic";
    private static final String HEADER_REALM = "realm";
    private static final String CRED_SEPARATOR = ":";
    private static final String CRAWLER_USER_AGENT = "gsa-crawler";

    /**
     * Class constructor
     */
    public CrawlingUtils() {
    }

    /**
     * Gets the basic Authorization Header
     * 
     * @param request servlet HTTP request
     * 
     * @return the authorization header
     */
    public static String getAuthorizationHeader(HttpServletRequest request) {

        String basicCred = null;

        try {
            if ((request.getHeader("Authorization") != null) && 
                (!request.getHeader("Authorization").equals(""))) {
                basicCred = request.getHeader("Authorization");
            }
        } catch (Exception ex) {
            logger.error("Error during Authorization Header (Authorization) acquisition: " + 
                         ex.getMessage(), ex);
        } finally {
        }

        return basicCred;

    }

    /**
     * Gets the Basic Credentials that are kept in the WWW-Authenticate 
     * Header (if any)
     * 
     * @param basicHeader HTTP Basic header
     * @param domain HTTP domain
     * @param authnID the authentication credential ID
     * 
     * @return Basic credentials
     */
    public static Credential getBasicCredentials(String basicHeader, 
                                                 String domain, 
                                                 String authnID) {

        Credential basicCred = null;

        try {

            if ((basicHeader != null) && (!basicHeader.equals(""))) {
                if (basicHeader.startsWith(HEADER_BASIC)) {
                    String credStr = 
                        basicHeader.substring(HEADER_BASIC.length());
                    logger.debug("Basic cred is: " + credStr);

                    //Decode the Header and get the credentials
                    byte[] basicByte = credStr.getBytes();
                    String basicCredential = 
                        new String(Base64.decodeBase64(basicByte));

                    //Get Username and password
                    String username = 
                        new String(basicCredential.substring(0, basicCredential.indexOf(CRED_SEPARATOR)));
                    String password = 
                        new String(basicCredential.substring(basicCredential.indexOf(CRED_SEPARATOR) + 
                                                             1));

                    logger.debug("Crawler: username [" + username + "]");

                    //Creating the Credential object
                    basicCred = new Credential(authnID);
                    basicCred.setUsername(username);
                    basicCred.setPassword(password);
                    basicCred.setDomain(domain);

                }
            }

        } catch (Exception ex) {
            logger.error("Error when getting Basic Credentials: " + ex);
        } finally {
        }

        return basicCred;

    }

    /**
     * Sends the WWW-Authenticate header for HTTP Basic
     * 
     * @param response servlet HTTP response
     * 
     * @param realm HTTP Basic realm
     */
    public static void sendAuthenticateHeader(HttpServletResponse response, 
                                              String realm) {

        String basicStr = null;

        if (realm == null) {
            basicStr = HEADER_BASIC;
        } else {
            basicStr = 
                    HEADER_BASIC + " " + HEADER_REALM + "=\"" + realm + "\"";
        }

        logger.debug("HTTP Basic response is " + basicStr);

        try {
            response.addHeader(HEADER_WWW_AUTHENTICATE, basicStr);
        } catch (Exception e) {
            logger.error("Error when setting Authenticate Header" + e);
        }

    }

    /**
     * Sends the WWW-Authenticate header for HTTP Basic with no realm
     * 
     * @param response servlet HTTP response
     */
    public static void sendAuthenticateHeader(HttpServletResponse response) {

        sendAuthenticateHeader(response, null);

    }

    /**
     * Checks if the user is crawler or not
     * 
     * @param request servlet HTTP request
     * 
     * @return if the userAgent contains the crawler info or not
     */
    public static boolean isCrawler(HttpServletRequest request) {

        boolean isCrawler = false;

        String userAgent = null;

        try {
            userAgent = request.getHeader("User-Agent");
            if ((userAgent != null) && (!userAgent.equals(""))) {
                if (userAgent.contains(CRAWLER_USER_AGENT)) {
                    isCrawler = true;
                }
            }
        } catch (Exception ex) {
            logger.error("Error when checking if user is crawler: " + ex);
        } finally {
        }

        return isCrawler;

    }


    /**
     * Checks if the request contains HTTP Basic header
     * 
     * @param request servlet HTTP request
     * 
     * @return if it request contains the Basic header
     */
    public static boolean doesContainBasicHeader(HttpServletRequest request) {

        boolean doesContainAuthZHeader = false;

        try {
            String authZHeader = getAuthorizationHeader(request);
            if (authZHeader != null) {
                if (authZHeader.startsWith(HEADER_BASIC)) {
                    doesContainAuthZHeader = true;
                }
            }
        } catch (Exception ex) {
            logger.error("Error when resolving if the Header contains Basic creds: " + 
                         ex);
        } finally {
        }

        return doesContainAuthZHeader;

    }

    /**
     * Transforms a set of cookies from Cookie Vector to an array
     * 
     * @param authCookies vector of authentication cookies
     * 
     * @return a Cookie array
     */
    public static Cookie[] transformCookiesToArray(Vector<Cookie> authCookies) {
        Cookie[] cookies = null;
        try {
            if (!authCookies.isEmpty()) {
                int vectorSize = authCookies.size();
                cookies = new Cookie[vectorSize];
                for (int i = 0; i < vectorSize; i++) {
                    cookies[i] = authCookies.elementAt(i);
                }
            }
        } catch (Exception ex) {
            logger.error("Error during cookie transformation: " + ex);
        } finally {
        }

        return cookies;

    }

    /**
     * Transforms a set of cookies from Cookie array to a vector
     * 
     * @param authCookies array of authentication Cookies
     * 
     * @return a Cookie vector
     */
    public static Vector<Cookie> transformCookiesToVector(Cookie[] authCookies) {
        Vector<Cookie> cookies = null;
        try {
            if (authCookies != null) {
                int arraySize = authCookies.length;
                cookies = new Vector<Cookie>();
                for (int i = 0; i < arraySize; i++) {
                    cookies.addElement(authCookies[i]);
                }
            }
        } catch (Exception ex) {
            logger.error("Error during cookie transformation: " + ex);
        } finally {
        }

        return cookies;

    }

    /**
     * Adds a new Cookie into the Cookie vector
     * 
     * @param cookies array of cookies
     * 
     * @param cookie the cookie to be added
     */
    public static void addCookie(Vector<Cookie> cookies, Cookie cookie) {
        //protection
        if (cookie != null) {
            //add cookie into the vector
            cookies.add(cookie);
        }
    }


    /**
     * Read the individual or range IP addresses from crawl request are only accepted
     * 
     * @return the IP addresses
     */
    public static IPAddressChecker getIPAddresses() {
        IPAddressChecker ipAddressChecker = IPAddressChecker.getInstance();
        if (ipAddressChecker.isEmpty()) {
            String ipAddressesStr = null;
            try {
                ipAddressesStr = 
                        Config.getConfig().getString(".gsa.ipAddress");
                if ((ipAddressesStr != null) && (!ipAddressesStr.equals(""))) {
                    logger.debug("Permitted IP Addresses are: " + 
                                 ipAddressesStr);
                    String[] ipAddressArray = 
                        getIPAddressesFromConfigFile(ipAddressesStr);
                    logger.debug("IPAddr array Length: " + 
                                 ipAddressArray.length);
                    for (int i = 0; i < ipAddressArray.length; i++) {
                        logger.debug("Adding new IP Address [" + 
                                     ipAddressArray[i] + "]");

                        IPAddresses ipAddresses = 
                            new IPAddresses(cleanIPAddress(ipAddressArray[i]));
                        ipAddressChecker.addAddress(ipAddresses);
                    }
                }
            } catch (Exception ex) {
                logger.error("Error when reading IP Addresses: " + 
                             ex.getMessage(), ex);
            } finally {
            }

        }
        return ipAddressChecker;
    }

    /**
     * Splits the IP addresses that are defined in the config file
     * 
     * @param ipAddresses the IP addresses read from the config file
     * 
     * @return an array containing all the IP addresses
     */
    private static String[] getIPAddressesFromConfigFile(String ipAddresses) {
        String[] ipAddressArray = null;
        if (ipAddresses != null || !ipAddresses.equalsIgnoreCase("")) {
            ipAddressArray = ipAddresses.split(",");
            logger.debug(ipAddresses + ":::" + ipAddressArray);
        }
        return ipAddressArray;
    }

    /**
     * Cleans IP addresses in case it'd contain any blanks
     * 
     * @param ipAddress the IP address read
     * 
     * @return the IP address without any blanks
     */
    private static String cleanIPAddress(String ipAddress) {
        return ipAddress.replaceAll("\\s", "");
    }

}
