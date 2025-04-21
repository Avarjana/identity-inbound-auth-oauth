/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.stub.OAuthServiceStub;
import org.wso2.carbon.identity.oauth.stub.types.Parameters;

/**
 * Client for OAuth service.
 */
public class OAuthServiceClient {

    private static final Log log = LogFactory.getLog(OAuthServiceClient.class);
    private OAuthServiceStub stub;

    /**
     * Instantiates OAuthServiceClient
     *
     * @param backendServerURL URL of the back end server where OAuthAdminService is running.
     * @param configCtx        ConfigurationContext
     * @throws org.apache.axis2.AxisFault
     */
    public OAuthServiceClient(String backendServerURL, ConfigurationContext configCtx)
            throws AxisFault {

        String serviceURL = backendServerURL + "OAuthService";
        if (log.isDebugEnabled()) {
            log.debug("Initializing OAuth service client with URL: {}", serviceURL);
        }
        stub = new OAuthServiceStub(configCtx, serviceURL);
    }

    public Parameters getAccessToken(Parameters params) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Getting access token for consumer key: {}", 
                    (params != null && params.getOauthConsumerKey() != null ? params.getOauthConsumerKey() : "N/A"));
        }
        return stub.getAccessToken(params);
    }

    public Parameters getOAuthApplicationData(Parameters params) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Getting OAuth application data for token: {}", 
                    (params != null && params.getOauthToken() != null ? params.getOauthToken() : "N/A"));
        }
        return stub.authorizeOauthRequestToken(params);
    }

    public Parameters getOauthRequestToken(Parameters params) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Getting OAuth request token for consumer key: {}", 
                    (params != null && params.getOauthConsumerKey() != null ? params.getOauthConsumerKey() : "N/A"));
        }
        return stub.getOauthRequestToken(params);
    }

    public Parameters authorizeOauthRequestToken(Parameters params) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Authorizing OAuth request token: {}", 
                    (params != null && params.getOauthToken() != null ? params.getOauthToken() : "N/A"));
        }
        return stub.authorizeOauthRequestToken(params);
    }

    public Parameters getScope(String token) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Getting scope for token: {}", token != null ? token : "N/A");
        }
        return stub.getScopeAndAppName(token);
    }

    public Parameters removeOAuthApplicationData(Parameters params) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Removing OAuth application data for consumer key: {}", 
                    (params != null && params.getOauthConsumerKey() != null ? params.getOauthConsumerKey() : "N/A"));
        }
        return stub.validateAuthenticationRequest(params);
    }
}
