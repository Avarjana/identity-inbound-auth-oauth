/*
 * Copyright (c) 2019-2024, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.client.authn.filter;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnService;

/**
 * Factory class to get OAuthClientAuthnService OSGI service.
 */
public class OAuthClientAuthnServiceFactory {

    private static final org.apache.commons.logging.Log log =
            org.apache.commons.logging.LogFactory.getLog(OAuthClientAuthnServiceFactory.class);
    private static final OAuthClientAuthnService SERVICE;

    static {
        if (log.isDebugEnabled()) {
            log.debug("Initializing OAuthClientAuthnService from OSGI context");
        }
        
        OAuthClientAuthnService oAuthClientAuthnService = (OAuthClientAuthnService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuthClientAuthnService.class, null);

        if (oAuthClientAuthnService == null) {
            log.error("OAuthClientAuthnService is not available from OSGI context");
            throw new IllegalStateException("OAuthClientAuthnService is not available from OSGI context.");
        }

        log.info("OAuthClientAuthnService successfully initialized");
        SERVICE = oAuthClientAuthnService;
    }

    public static OAuthClientAuthnService getOAuthClientAuthnService() {
        if (log.isDebugEnabled()) {
            log.debug("Returning OAuthClientAuthnService instance");
        }
        return SERVICE;
    }
}
