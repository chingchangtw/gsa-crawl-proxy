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

package com.google.gsa.proxy.config;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.log4j.Logger;


/**
 * It implements the configuration functionalities to read the config 
 * file in the crawl proxy application. It uses the Apache Commons configuration
 * framework.
 * 
 */
public class Config {

    //logger
    private static Logger logger = Logger.getLogger(Config.class);

    //XML config
    private static XMLConfiguration config;

    private static final String DEFAULT_CONFIG_PATH = 
        "config/crawlerConfig.xml";

    private static String crawlerConfigPath = null;

    /**
     * Class constructor
     */
    public Config() {
    }

    /**
     * This method returns the singleton. It has to be called this way at least
     * the first time to set up the config file path properly
     * 
     * @param configPath XML crawler config path location
     * 
     * @return XML configuration instance
     * 
     * @throws ConfigurationException
     */
    public static XMLConfiguration getConfig(String configPath) throws ConfigurationException {
        if (config == null) {
            //Set crawler config path and initialize Config
            setCrawlerConfigPath(configPath);
            try {
                init();
            } catch (ConfigurationException e) {
                throw e;
            }
        }
        return config;
    }

    /**
     * This method returns the singleton. It's equivalent to the previous one but 
     * you don't have to include here the config file path
     * 
     * @return XML configuration instance
     * 
     * @throws ConfigurationException
     */
    public static XMLConfiguration getConfig() throws ConfigurationException {
        if (config == null) {
            //raise exception returning error
            throw new ConfigurationException("A config file location has to be provided first: getConfig(String configPath)");
        }
        return config;
    }

    /**
     * Sets the Crawl Proxy config path
     * 
     * @param configPath the location of the config file
     */
    private static void setCrawlerConfigPath(String configPath) {
        crawlerConfigPath = configPath;
    }

    /**
     * Initilizes the configuration class
     * 
     * @throws ConfigurationException
     */
    private static void init() throws ConfigurationException {

        //Point to the correct Config File
        String configFile = null;
        if ((crawlerConfigPath != null) && (!crawlerConfigPath.equals(""))) {
            configFile = crawlerConfigPath;
        } else {
            configFile = DEFAULT_CONFIG_PATH;
        }

        try {
            config = new XMLConfiguration(configFile);
        } catch (ConfigurationException e) {
            throw e;
        }
        config.setReloadingStrategy(new FileChangedReloadingStrategy());
        config.setAutoSave(true);
        logger.info("Configuration loaded: " + configFile);
    }

    /**
     * Gets the value of a config parameter
     * 
     * @param configString the name of the configuration parameter
     * 
     * @return the value of that parameter (if any)
     * 
     * @throws ConfigurationException
     */
    public static String getConfigString(String configString) throws ConfigurationException {
        String aString = Config.getConfig().getString(configString);
        if (aString == null) {
            logger.error("Config is not available");
            return null;
        } else {
            return aString.trim();
        }

    }

}
