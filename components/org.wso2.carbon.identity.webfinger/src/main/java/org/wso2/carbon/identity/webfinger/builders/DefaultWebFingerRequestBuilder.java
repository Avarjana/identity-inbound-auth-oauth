/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.webfinger.builders;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.webfinger.WebFingerConstants;
import org.wso2.carbon.identity.webfinger.WebFingerEndpointException;
import org.wso2.carbon.identity.webfinger.WebFingerRequest;
import org.wso2.carbon.identity.webfinger.internal.WebFingerServiceComponentHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * Default implementation of WebFingerRequestBuilder interface
 */
public class DefaultWebFingerRequestBuilder implements WebFingerRequestBuilder {

    private static final Log log = LogFactory.getLog(DefaultWebFingerRequestBuilder.class);

    @Override
    public WebFingerRequest buildRequest(HttpServletRequest request) throws WebFingerEndpointException {
        if (log.isDebugEnabled()) {
            log.debug("Building WebFinger request from HTTP parameters");
        }
        
        WebFingerRequest webFingerRequest = new WebFingerRequest();
        List<String> parameters = Collections.list(request.getParameterNames());
        
        if (parameters.size() != 2 || !parameters.contains(WebFingerConstants.REL) || !parameters.contains
                (WebFingerConstants.RESOURCE)) {
            log.warn("Invalid WebFinger request parameters. Expected: rel and resource, Found: {}", parameters);
            throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_REQUEST, "Bad Web " +
                    "Finger request.");
        }
        
        webFingerRequest.setServletRequest(request);
        String resource = request.getParameter(WebFingerConstants.RESOURCE);
        String rel = request.getParameter(WebFingerConstants.REL);
        webFingerRequest.setRel(rel);
        webFingerRequest.setResource(resource);
        
        if (log.isDebugEnabled()) {
            log.debug("WebFinger request parameters - rel: {}, resource: {}", rel, resource);
        }

        if (StringUtils.isBlank(resource)) {
            log.warn("Can't normalize null or empty URI: {}", resource);
            throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, "Null or empty URI.");
        } else {
            URI resourceURI = URI.create(resource);
            if (StringUtils.isBlank(resourceURI.getScheme())) {
                log.warn("WebFinger resource scheme is empty for resource: {}", resource);
                throw new WebFingerEndpointException("Scheme of the resource cannot be empty");
            }
            
            String userInfo;
            if (WebFingerConstants.ACCT_SCHEME.equals(resourceURI.getScheme())) {
                //acct scheme
                userInfo = resourceURI.getSchemeSpecificPart();
                if (!userInfo.contains("@")) {
                    log.warn("Invalid host value in acct scheme for resource: {}", resource);
                    throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_REQUEST,
                            "Invalid host value.");
                }
                userInfo = userInfo.substring(0, userInfo.lastIndexOf('@'));
                if (log.isDebugEnabled()) {
                    log.debug("Extracted userInfo from acct scheme: {}", userInfo);
                }
            } else {
                //https scheme
                userInfo = resourceURI.getUserInfo();
                webFingerRequest.setScheme(resourceURI.getScheme());
                webFingerRequest.setHost(resourceURI.getHost());
                webFingerRequest.setPort(resourceURI.getPort());
                webFingerRequest.setPath(resourceURI.getPath());
                webFingerRequest.setQuery(resourceURI.getQuery());
                
                if (log.isDebugEnabled()) {
                    log.debug("Extracted URI components - scheme: {}, host: {}, port: {}, path: {}", 
                            resourceURI.getScheme(), resourceURI.getHost(), resourceURI.getPort(), resourceURI.getPath());
                }
            }

            String tenant;
            if (StringUtils.isNotBlank(userInfo)) {
                try {
                    userInfo = URLDecoder.decode(userInfo, "UTF-8");
                    if (log.isDebugEnabled()) {
                        log.debug("Decoded userInfo: {}", userInfo);
                    }
                } catch (UnsupportedEncodingException e) {
                    log.error("Error decoding userInfo: {}", userInfo, e);
                    throw new WebFingerEndpointException("Cannot decode the userinfo");
                }
                tenant = MultitenantUtils.getTenantDomain(userInfo);
                webFingerRequest.setUserInfo(resourceURI.getUserInfo());
            } else {
                tenant = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                if (log.isDebugEnabled()) {
                    log.debug("No userInfo found, using super tenant domain");
                }
            }
            validateTenant(tenant);
            webFingerRequest.setTenant(tenant);
            
            if (log.isDebugEnabled()) {
                log.debug("WebFinger request built successfully for tenant: {}", tenant);
            }
        }

        return webFingerRequest;
    }

    public static void validateTenant(String tenantDomain) throws WebFingerEndpointException {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Validating tenant domain: {}", tenantDomain);
            }
            
            int tenantId = WebFingerServiceComponentHolder.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
                    
            if (tenantId < 0 && tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                log.warn("Invalid tenant domain in WebFinger request: {}", tenantDomain);
                throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, "The tenant " +
                        "domain is not valid.");
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Tenant validation successful for tenant domain: {}, tenantId: {}", tenantDomain, tenantId);
            }
        } catch (UserStoreException e) {
            log.error("Error occurred while validating tenant domain: {}", tenantDomain, e);
            throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, e.getMessage());
        }
    }


}
