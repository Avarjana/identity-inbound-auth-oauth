/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.extension.utils;

import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;
import org.wso2.carbon.identity.oauth.extension.engine.impl.JSEngineImpl;
import org.wso2.carbon.identity.oauth.extension.engine.impl.OpenJdkJSEngineImpl;

import static org.wso2.carbon.identity.oauth.extension.utils.Constants.JDK_SCRIPT_CLASS_NAME;
import static org.wso2.carbon.identity.oauth.extension.utils.Constants.OPENJDK_SCRIPT_CLASS_NAME;

/**
 * Utility class for JSEngine.
 */
public class EngineUtils {
    
    private static final Logger log = LogManager.getLogger(EngineUtils.class);

    /**
     * Get the JSEngine based on the configuration.
     *
     * @return JSEngine instance.
     */
    public static JSEngine getEngineFromConfig() {

        log.debug("Getting JS engine from configuration");
        String scriptEngineName = IdentityUtil.getProperty(FrameworkConstants.SCRIPT_ENGINE_CONFIG);
        if (scriptEngineName != null) {
            log.debug("Script engine configured: {}", scriptEngineName);
            if (StringUtils.equalsIgnoreCase(FrameworkConstants.OPENJDK_NASHORN, scriptEngineName)) {
                log.info("Using OpenJDK Nashorn JavaScript engine as configured in framework settings");
                return OpenJdkJSEngineImpl.getInstance();
            } else {
                log.debug("Configured script engine '{}' is not OpenJDK Nashorn, falling back to auto-detection", 
                        scriptEngineName);
            }
        } else {
            log.debug("No script engine configured in framework settings, detecting available engine");
        }
        return getEngineBasedOnAvailability();
    }

    private static JSEngine getEngineBasedOnAvailability() {

        log.debug("Auto-detecting available JavaScript engine for OAuth extension");
        try {
            Class.forName(OPENJDK_SCRIPT_CLASS_NAME);
            log.info("OpenJDK Nashorn JavaScript engine detected and will be used for OAuth extension");
            return OpenJdkJSEngineImpl.getInstance();
        } catch (ClassNotFoundException e) {
            log.debug("OpenJDK Nashorn engine not available in classpath: {}", e.getMessage());
            try {
                Class.forName(JDK_SCRIPT_CLASS_NAME);
                log.info("JDK Nashorn JavaScript engine detected and will be used for OAuth extension");
                return JSEngineImpl.getInstance();
            } catch (ClassNotFoundException classNotFoundException) {
                log.error("JavaScript engine initialization failed. Neither OpenJDK nor JDK Nashorn engines found in classpath");
                log.debug("OpenJDK class lookup failed with: {}, JDK class lookup failed with: {}", 
                        e.getMessage(), classNotFoundException.getMessage());
                return null;
            }
        }
    }
}
