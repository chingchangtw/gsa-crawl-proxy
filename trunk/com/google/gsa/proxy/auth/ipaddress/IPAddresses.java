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


import java.net.UnknownHostException;

import org.apache.log4j.Logger;

/**
 * It represents an IP address that can be either an individual IPAddress or a
 * range (with an initial and final addresses).
 * 
 * @see IPAddressChecker
 * @see IPAddresses
 * 
 */
public class IPAddresses {


    //Initial IP Address
    private IPAddress initialIPAddress = null;

    //Final IP Address (only if it's a range)
    private IPAddress finalIPAddress = null;

    //Is it range of IP Addresses
    private boolean isRange = false;

    //Range Delimiter
    private static final String RANGE = "-";

    //logger instance
    private Logger logger = Logger.getLogger(IPAddress.class);


    /**
     * Class constructor
     */
    public IPAddresses() {
    }

    /**
     * Class constructor passing a string including an individual IP or a range
     * 
     * @param ipAddresses string that contains the IP address(es)
     */
    public IPAddresses(String ipAddresses) {
        //protection
        if (ipAddresses != null) {
            checkIPAddress(ipAddresses);
        }
    }


    /**
     * Sets the initial IP address, both for individual or range IPs
     * 
     * @param initialIPAddress IP address
     */
    public void setInitialIPAddress(IPAddress initialIPAddress) {
        this.initialIPAddress = initialIPAddress;
    }

    /**
     * Gets the initial IP address
     * 
     * @return ip address
     */
    public IPAddress getInitialIPAddress() {
        return initialIPAddress;
    }

    /**
     * Sets the final IP address of a range
     * 
     * @param finalIPAddress IP address
     */
    public void setFinalIPAddress(IPAddress finalIPAddress) {
        this.finalIPAddress = finalIPAddress;
    }

    /**
     * Gets the final IP address of a range
     * 
     * @return IP address
     */
    public IPAddress getFinalIPAddress() {
        return finalIPAddress;
    }

    /**
     * Sets if it's an IP address range
     * 
     * @param isRange boolean that sets if it's a range or not
     */
    public void setIsRange(boolean isRange) {
        this.isRange = isRange;
    }

    /**
     * Gets if the IP address is a range or not
     * 
     * @return if it's a range or not
     */
    public boolean isRange() {
        return isRange;
    }

    /**
     * Reads the IP address and configures the class properly if it's an
     * individual IP address or a range
     * 
     * @param ipAddresses IP address string coming from the config file
     */
    private void checkIPAddress(String ipAddresses) {


        try {
            //check if it contains the Range character
            int containsRange = ipAddresses.indexOf(RANGE);

            if (containsRange < 0) {
                //it does not contain an IP range
                isRange = false;

                //Setting the initial (unique) IP Address                 
                initialIPAddress = new IPAddress(ipAddresses);

                //Forcing final IP Address to be null
                finalIPAddress = null;


            } else {
                //it contains an IP range
                isRange = true;

                //Setting Addresses
                initialIPAddress = 
                        new IPAddress(ipAddresses.substring(0, containsRange));
                finalIPAddress = 
                        new IPAddress(ipAddresses.substring(containsRange + 1, 
                                                            ipAddresses.length()));

            }
        } catch (UnknownHostException uHE) {
            logger.error("Unknown Host Exception when checking it's an IP range: " + 
                         uHE.getMessage(), uHE);
        } catch (Exception ex) {
            logger.error("Error when checking it's an IP range: " + 
                         ex.getMessage(), ex);
        }

    }

}
