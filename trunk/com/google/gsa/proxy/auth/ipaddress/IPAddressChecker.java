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

import java.util.Vector;

import org.apache.log4j.Logger;

/**
 * This class processes the permitted IP addresses defined in the 
 * configuration files and checks the crawl requests are coming from
 * servers included in this restricted list.
 * 
 * @see IPAddress
 * @see IPAddresses
 * 
 */
public class IPAddressChecker {

    //logger instance
    private Logger logger = Logger.getLogger(IPAddress.class);

    //IPAddresses vector
    private static Vector<IPAddresses> ipAddressVector = 
        new Vector<IPAddresses>();

    //Singleton instance
    private static IPAddressChecker ipAddressChecker = null;


    /**
     * Class constructor
     */
    private IPAddressChecker() {
    }

    /**
     * Gets the unique IPAddressChecker instance. It implements a 
     * singleton pattern.
     * 
     * @return the IPAddressChecker reference
     */
    public static IPAddressChecker getInstance() {

        if (ipAddressChecker == null) {
            ipAddressChecker = new IPAddressChecker();
        }

        return ipAddressChecker;
    }

    /**
     * Adds a new address into the permitted list
     * 
     * @param ipAddresses IP address (individual or range)
     */
    public void addAddress(IPAddresses ipAddresses) {
        synchronized (ipAddressVector) {
            if (!ipAddressVector.contains(ipAddresses)) {
                logger.debug("Adding new IP Address [" + 
                             ipAddresses.getInitialIPAddress().toString() + 
                             "]");
                ipAddressVector.add(ipAddresses);
            }
        }
    }

    /**
     * Deletes an existing address from the restricted list
     * 
     * @param ipAddresses IP address (individual or range)
     */
    public void removeAddress(IPAddresses ipAddresses) {
        synchronized (ipAddressVector) {
            if (ipAddressVector.contains(ipAddresses)) {
                logger.debug("Removing IP Address [" + 
                             ipAddresses.getInitialIPAddress().toString() + 
                             "]");
                ipAddressVector.remove(ipAddresses);
            }
        }
    }

    /**
     * Checks if an IP address is included in the permitted list
     * 
     * @param testingIPAddresses IP address to be checked
     * 
     * @return if the IP address is part of the restricted access list
     */
    public boolean isIPAddressIncluded(IPAddresses testingIPAddresses) {

        boolean isIPAddressIncluded = false;

        //protection
        if (testingIPAddresses != null) {

            IPAddress testingIPAddress = 
                testingIPAddresses.getInitialIPAddress();

            if (!ipAddressVector.isEmpty()) {

                logger.debug("IP Address Vector is not empty");

                //Iterate over the vector to check if the IP address is included
                for (int i = 0; i < ipAddressVector.size(); i++) {

                    IPAddresses ipAddressV = ipAddressVector.get(i);

                    if (ipAddressV.isRange()) {

                        logger.debug("IP Address to check is a Range");

                        isIPAddressIncluded = 
                                isBetween(testingIPAddress, ipAddressV);

                        if (isIPAddressIncluded) {
                            logger.debug("IP Address [" + 
                                         testingIPAddress.getIPAddress().toString() + 
                                         "] is included in the range [" + 
                                         ipAddressV.getInitialIPAddress().getIPAddress().toString() + 
                                         " - " + 
                                         ipAddressV.getFinalIPAddress().getIPAddress().toString() + 
                                         "]");
                            break;
                        }

                    } else {
                        logger.debug("IP Address to check is NOT a Range");
                        //It's not range
                        long testingIPAddressLong = toLong(testingIPAddress);
                        long ipAddressVLong = 
                            toLong(ipAddressV.getInitialIPAddress());
                        if (testingIPAddressLong == ipAddressVLong) {

                            logger.debug("IP Address [" + 
                                         testingIPAddress.getIPAddress().toString() + 
                                         "] is included in the vector");
                            isIPAddressIncluded = true;
                            break;

                        }
                    }

                }

            }
        }

        return isIPAddressIncluded;
    }


    /**
     * Use this method to verify if a given IP address is between a range defined
     * by two IP addresses.  
     *
     * @param testingIPAddress - The IP address to verify.
     * @param ipAddressRange - range.
     *
     * @return boolean - true if testingIPAddress is in between of the range
     * false otherwise.
     */
    private boolean isBetween(IPAddress testingIPAddress, 
                              IPAddresses ipAddressRange) {

        boolean isBetween = false;

        long tested = toLong(testingIPAddress);
        long addr1 = toLong(ipAddressRange.getInitialIPAddress());
        long addr2 = toLong(ipAddressRange.getFinalIPAddress());

        long lowerLimit = Math.min(addr1, addr2);
        long upperLimit = Math.max(addr1, addr2);

        logger.debug("Tested IP: " + tested + " has to be greater than " + 
                     lowerLimit + " and lower than " + upperLimit);

        if ((lowerLimit <= tested) && (tested <= upperLimit)) {
            isBetween = true;
        }

        return isBetween;
    }

    /**
     * Converts the IP address to a long value. It helps to compare an 
     * IP address with others
     *
     * @param ipAddress - The ipAddress to be converted.
     * 
     * @return the long representation of the IP Address
     */
    private long toLong(IPAddress ipAddress) {
        long compacted = 0;
        InetAddress inetAddress = ipAddress.getIPAddress();
        byte[] bytes = inetAddress.getAddress();

        //convert to long from bytes
        compacted = convertToLong(bytes);

        return compacted;
    }

    /**
     * Converts a byte to a long value
     * 
     * @param b it's the byte to be converted 
     * 
     * @return long value
     */
    private static long byteToLong(byte b) {
        long r = (long)b;
        if (r < 0)
            r += 256;
        return r;
    }


    /**
     * The convertToLong method takes an array of bytes and shifts them into a
     * long value.
     * 
     * @param addr the byte array to convert to a long.
     * 
     * @return the created long value.
     * 
     * @exception IllegalArgumentException
     *                Thrown if the addr parameter is null.
     * 
     */
    public static long convertToLong(byte[] addr) {

        if (addr == null)
            throw new IllegalArgumentException("The passed array must not be null");

        long address = 0;
        for (int i = 0; i < addr.length; i++) {
            address <<= 8;
            address |= byteToLong(addr[i]);
        }
        return address;

    }

    /**
     * Checks id the IP Address list is empty
     * 
     * @return if the IP Address list is empty or not
     */
    public boolean isEmpty() {
        return ipAddressVector.isEmpty();
    }


}
