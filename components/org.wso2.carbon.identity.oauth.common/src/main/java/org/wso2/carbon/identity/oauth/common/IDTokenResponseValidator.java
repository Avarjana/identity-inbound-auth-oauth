/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.common;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.validator.TokenValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.SCOPE;

/**
 * Validator for ID token response.
 */
public class IDTokenResponseValidator extends TokenValidator {

    private static final Log log = LogFactory.getLog(IDTokenResponseValidator.class);

    public IDTokenResponseValidator() {

    }

    /**
     * Method to check whether the scope parameter string contains 'openid' as a scope.
     *
     * @param scope
     * @return
     */
    private static boolean containOIDCScope(String scope) {

        String[] scopeArray = scope.split("\\s+");
        for (String openidscope : scopeArray) {
            if (openidscope.equals(OAuthConstants.Scope.OPENID)) {
                return true;
            }
        }
        return false;
    }

    public void validateRequiredParameters(HttpServletRequest request) throws OAuthProblemException {

        if (log.isDebugEnabled()) {
            log.debug("Validating required parameters for id_token response");
        }
        
        super.validateRequiredParameters(request);

        // for id_token response type, the scope parameter should contain 'openid' as one of the scopes.
        String openIdScope = request.getParameter(SCOPE);
        
        if (log.isDebugEnabled()) {
            log.debug("Validating openid scope for id_token response. Scope: {}", openIdScope);
        }
        
        if (StringUtils.isBlank(openIdScope) || !containOIDCScope(openIdScope)) {
            log.warn("Invalid request: openid scope not found for id_token response. Scope: {}", openIdScope);
            throw OAuthProblemException.error(OAuthError.TokenResponse.INVALID_REQUEST)
                    .description("\'response_type\' contains \'id_token\'; but \'openid\' scope not found.");
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Required parameter validation successful for id_token response");
        }
    }

    @Override
    public void validateMethod(HttpServletRequest request) throws OAuthProblemException {

        String method = request.getMethod();
        if (log.isDebugEnabled()) {
            log.debug("Validating HTTP method for id_token response: {}", method);
        }
        
        if (!OAuth.HttpMethod.GET.equals(method) && !OAuth.HttpMethod.POST.equals(method)) {
            log.warn("Invalid HTTP method for id_token response: {}. Only GET and POST methods are allowed", method);
            throw OAuthProblemException.error(OAuthError.CodeResponse.INVALID_REQUEST)
                    .description("Method not correct.");
        }
        
        if (log.isDebugEnabled()) {
            log.debug("HTTP method validation successful for id_token response");
        }
    }

    @Override
    public void validateContentType(HttpServletRequest request) throws OAuthProblemException {
        if (log.isDebugEnabled()) {
            log.debug("Content type validation skipped for id_token response");
        }
    }
}
