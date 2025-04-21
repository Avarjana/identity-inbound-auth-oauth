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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.oauth.common.OAuthCommonUtil.validateContentTypes;

/**
 * This class used to validate the SAML2 grant.
 */
public class SAML2GrantValidator extends AbstractValidator<HttpServletRequest> {

    private static final Log log = LogFactory.getLog(SAML2GrantValidator.class);

    public SAML2GrantValidator() {

        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        requiredParams.add(OAuth.OAUTH_ASSERTION);
        
        if (log.isDebugEnabled()) {
            log.debug("Initialized SAML2GrantValidator with required parameters: {} and {}", 
                    OAuth.OAUTH_GRANT_TYPE, OAuth.OAUTH_ASSERTION);
        }
    }

    @Override
    public void validateContentType(HttpServletRequest request) throws OAuthProblemException {

        if (log.isDebugEnabled()) {
            log.debug("Validating content type for SAML2 grant request");
        }
        validateContentTypes(request);
        if (log.isDebugEnabled()) {
            log.debug("Content type validation successful for SAML2 grant request");
        }
    }
}
