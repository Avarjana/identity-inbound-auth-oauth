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
            log.debug("Building WebFinger request from HTTP request from: {}", request.getRemoteAddr());
        }
        
        WebFingerRequest webFingerRequest = new WebFingerRequest();
        List<String> parameters = Collections.list(request.getParameterNames());
        
        if (log.isDebugEnabled()) {
            log.debug("WebFinger request parameters: {}", String.join(", ", parameters));
        }
        
        if (parameters.size() != 2 || !parameters.contains(WebFingerConstants.REL) || !parameters.contains
                (WebFingerConstants.RESOURCE)) {
            String errorMsg = "Bad WebFinger request. Required parameters 'rel' and 'resource' must be present";
            log.warn(errorMsg);
            throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_REQUEST, errorMsg);
        }
        webFingerRequest.setServletRequest(request);
        String resource = request.getParameter(WebFingerConstants.RESOURCE);
        webFingerRequest.setRel(request.getParameter(WebFingerConstants.REL));
        webFingerRequest.setResource(resource);

        if (StringUtils.isBlank(resource)) {
            log.warn("Can't normalize null or empty URI in WebFinger request");
            throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, "Null or empty URI.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Processing WebFinger resource URI: {}", resource);
            }
            
            URI resourceURI = URI.create(resource);
            if (StringUtils.isBlank(resourceURI.getScheme())) {
                String errorMsg = "Scheme of the resource URI cannot be empty";
                log.warn(errorMsg);
                throw new WebFingerEndpointException("Scheme of the resource cannot be empty");
            }
            String userInfo;
            if (WebFingerConstants.ACCT_SCHEME.equals(resourceURI.getScheme())) {
                // acct scheme
                if (log.isDebugEnabled()) {
                    log.debug("Processing 'acct' scheme URI");
                }
                
                userInfo = resourceURI.getSchemeSpecificPart();
                if (!userInfo.contains("@")) {
                    String errorMsg = "Invalid host value in acct URI - missing @ symbol";
                    log.warn(errorMsg);
                    throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_REQUEST, errorMsg);
                }
                userInfo = userInfo.substring(0, userInfo.lastIndexOf('@'));
                
                if (log.isDebugEnabled()) {
                    log.debug("Extracted user info from acct URI: {}", userInfo);
                }
            } else {
                // https or other scheme
                if (log.isDebugEnabled()) {
                    log.debug("Processing '{}' scheme URI", resourceURI.getScheme());
                }
                
                userInfo = resourceURI.getUserInfo();
                webFingerRequest.setScheme(resourceURI.getScheme());
                webFingerRequest.setHost(resourceURI.getHost());
                webFingerRequest.setPort(resourceURI.getPort());
                webFingerRequest.setPath(resourceURI.getPath());
                webFingerRequest.setQuery(resourceURI.getQuery());
                
                if (log.isDebugEnabled()) {
                    log.debug("Extracted components - host: {}, port: {}, path: {}", 
                            resourceURI.getHost(), resourceURI.getPort(), resourceURI.getPath());
                }
            }

            String tenant;
            if (StringUtils.isNotBlank(userInfo)) {
                try {
                    userInfo = URLDecoder.decode(userInfo, "UTF-8");
                    if (log.isDebugEnabled()) {
                        log.debug("URL-decoded user info: {}", userInfo);
                    }
                } catch (UnsupportedEncodingException e) {
                    String errorMsg = "Cannot decode the user info with UTF-8 encoding";
                    log.error(errorMsg, e);
                    throw new WebFingerEndpointException(errorMsg);
                }
                tenant = MultitenantUtils.getTenantDomain(userInfo);
                webFingerRequest.setUserInfo(resourceURI.getUserInfo());
                
                if (log.isDebugEnabled()) {
                    log.debug("Extracted tenant domain from user info: {}", tenant);
                }
            } else {
                tenant = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                if (log.isDebugEnabled()) {
                    log.debug("No user info present, using super tenant domain");
                }
            }
            validateTenant(tenant);
            webFingerRequest.setTenant(tenant);
        }

        return webFingerRequest;
    }

    public static void validateTenant(String tenantDomain) throws WebFingerEndpointException {
        if (log.isDebugEnabled()) {
            log.debug("Validating tenant domain: {}", tenantDomain);
        }
        
        try {
            int tenantId = WebFingerServiceComponentHolder.getRealmService().getTenantManager().getTenantId(tenantDomain);
            
            if (log.isDebugEnabled()) {
                log.debug("Tenant ID for domain '{}': {}", tenantDomain, tenantId);
            }
            
            if (tenantId < 0 && tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                String errorMsg = "The tenant domain '" + tenantDomain + "' is not valid";
                log.warn(errorMsg);
                throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, errorMsg);
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Tenant domain '{}' validation successful", tenantDomain);
            }
        } catch (UserStoreException e) {
            String errorMsg = "Error validating tenant domain: " + tenantDomain;
            log.error(errorMsg, e);
            throw new WebFingerEndpointException(WebFingerConstants.ERROR_CODE_INVALID_RESOURCE, e.getMessage());
        }
    }


}
