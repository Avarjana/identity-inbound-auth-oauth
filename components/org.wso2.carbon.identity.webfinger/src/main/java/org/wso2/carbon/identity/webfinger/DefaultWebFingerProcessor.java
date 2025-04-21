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

package org.wso2.carbon.identity.webfinger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.webfinger.builders.DefaultWebFingerRequestBuilder;
import org.wso2.carbon.identity.webfinger.builders.WebFingerOIDCResponseBuilder;
import org.wso2.carbon.identity.webfinger.builders.WebFingerRequestBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Singleton class to process the webfinger request.
 */
public class DefaultWebFingerProcessor implements WebFingerProcessor {
    private static final Log log = LogFactory.getLog(DefaultWebFingerProcessor.class);
    private static DefaultWebFingerProcessor defaultWebFingerProcessor = new DefaultWebFingerProcessor();

    private DefaultWebFingerProcessor() {
        if (log.isDebugEnabled()) {
            log.debug("Initializing OIDCProcessor for OpenID connect discovery processor.");
        }
    }

    public static DefaultWebFingerProcessor getInstance() {
        return defaultWebFingerProcessor;
    }

    public WebFingerResponse getResponse(HttpServletRequest request) throws WebFingerEndpointException,
            ServerConfigurationException {
        if (log.isDebugEnabled()) {
            log.debug("Building WebFinger request object from HTTP request");
        }
        WebFingerRequestBuilder requestBuilder = new DefaultWebFingerRequestBuilder();
        WebFingerRequest requestObject = requestBuilder.buildRequest(request);
        
        if (log.isDebugEnabled()) {
            log.debug("WebFinger request built successfully for resource: {}", requestObject.getResource());
        }
        
        WebFingerOIDCResponseBuilder responseBuilder = new WebFingerOIDCResponseBuilder();
        WebFingerResponse response = responseBuilder.buildWebFingerResponse(requestObject);
        
        if (log.isDebugEnabled()) {
            log.debug("WebFinger response built successfully for resource: {}", requestObject.getResource());
        }
        
        return response;
    }

    public int handleError(WebFingerEndpointException error) {
        String errorCode = error.getErrorCode();
        if (WebFingerConstants.ERROR_CODE_INVALID_REQUEST.equals(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid WebFinger request: {}", error.getMessage());
            }
            return HttpServletResponse.SC_BAD_REQUEST;
        } else if (WebFingerConstants.ERROR_CODE_INVALID_RESOURCE.equals(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid resource in WebFinger request: {}", error.getMessage());
            }
            return HttpServletResponse.SC_NOT_FOUND;
        } else if (WebFingerConstants.ERROR_CODE_JSON_EXCEPTION.equals(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug("JSON processing error in WebFinger request: {}", error.getMessage());
            }
            return HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE;
        } else if (WebFingerConstants.ERROR_CODE_NO_WEBFINGER_CONFIG.equals(errorCode)) {
            log.error("WebFinger configuration not found: {}", error.getMessage(), error);
            return HttpServletResponse.SC_NOT_FOUND;
        } else {
            log.error("Internal server error occurred while processing WebFinger request: {}", error.getMessage(), error);
            return HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        }
    }
}
