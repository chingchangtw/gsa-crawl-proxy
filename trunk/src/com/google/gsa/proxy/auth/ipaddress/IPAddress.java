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

package com.google.gsa.proxy.auth.ipaddress;

import java.net.InetAddress;

import java.net.UnknownHostException;

import org.apache.log4j.Logger;

/**
 * Represents an individual IP Address instance. This is used for implementing an 
 * IP Address checker that only permits to access to the crawl proxy 
 * from a list of restricted IP addresses that should be just the ones 
 * associated to the appliances
 * 
 * @see IPAddressChecker
 * @see IPAddresses
 * 
 */
public class IPAddress {

    //IP Address
    private InetAddress iPAddress = null;

    //logger instance
    private Logger logger = Logger.getLogger(IPAddress.class);

    /**
     * Class constructor
     */
    public IPAddress() {
    }

    /**
     * Class constructor passing an IP Address (String format)
     * 
     * @param iPAddressStr IP address
     * 
     * @throws UnknownHostException
     */
    public IPAddress(String iPAddressStr) throws UnknownHostException {
        //protection        
        if (iPAddressStr != null) {
            logger.debug("IP Address is [" + iPAddressStr + "]");
            try {
                InetAddress[] iPAddresses = 
                    InetAddress.getAllByName(iPAddressStr);
                if (iPAddresses.length >= 1) {
                    this.iPAddress = iPAddresses[0];
                    logger.debug("Host Address is:  " + 
                                 iPAddress.getHostAddress());
                }
            } catch (UnknownHostException e) {
                logger.error("Error when setting IP Address [" + iPAddressStr + 
                             "]: " + e.getMessage(), e);
                throw e;
            }
        }
    }

    /**
     * Class constructor passing an IP Address (InetAddress format)
     * 
     * @param iPAddress IP address
     */
    public IPAddress(InetAddress iPAddress) {
        setIPAddress(iPAddress);
    }

    /**
     * Sets the IP Address
     * 
     * @param iPAddress IP Address
     */
    public void setIPAddress(InetAddress iPAddress) {
        this.iPAddress = iPAddress;
    }

    /**
     * Gets the IP Address
     *  
     * @return IP address
     */
    public InetAddress getIPAddress() {
        return iPAddress;
    }
}
