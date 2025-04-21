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

package org.wso2.carbon.identity.discovery.builders;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.ExternalClaim;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.discovery.OIDCDiscoveryEndPointException;
import org.wso2.carbon.identity.discovery.OIDProviderConfigResponse;
import org.wso2.carbon.identity.discovery.OIDProviderRequest;
import org.wso2.carbon.identity.discovery.internal.OIDCDiscoveryDataHolder;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Set;

import static org.wso2.carbon.identity.discovery.DiscoveryUtil.isUseEntityIdAsIssuerInOidcDiscovery;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_FLOW_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildServiceUrl;

/**
 * ProviderConfigBuilder builds the OIDProviderConfigResponse
 * giving the correct OprnIDConnect settings.
 * This should handle all the services to get the required data.
 */
public class ProviderConfigBuilder {

    private static final Log log = LogFactory.getLog(ProviderConfigBuilder.class);
    private static final String OIDC_CLAIM_DIALECT = "http://wso2.org/oidc/claim";

    public OIDProviderConfigResponse buildOIDProviderConfig(OIDProviderRequest request) throws
            OIDCDiscoveryEndPointException, ServerConfigurationException {
        if (log.isDebugEnabled()) {
            log.debug("Building OIDC provider configuration for tenant: {}", request.getTenantDomain());
        }
        OIDProviderConfigResponse providerConfig = new OIDProviderConfigResponse();
        String tenantDomain = request.getTenantDomain();
        if (isUseEntityIdAsIssuerInOidcDiscovery()) {
            try {
                String issuer = OAuth2Util.getIdTokenIssuer(tenantDomain);
                providerConfig.setIssuer(issuer);
                if (log.isDebugEnabled()) {
                    log.debug("Using entity ID as issuer in OIDC discovery: {}", issuer);
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Error while retrieving OIDC ID token issuer value for tenant: {}", tenantDomain, e);
                throw new ServerConfigurationException(String.format("Error while retrieving OIDC Id token issuer " +
                        "value for tenant domain: %s", tenantDomain), e);
            }
        } else {
            String issuer = OAuth2Util.getIDTokenIssuer();
            providerConfig.setIssuer(issuer);
            if (log.isDebugEnabled()) {
                log.debug("Using default issuer in OIDC discovery: {}", issuer);
            }
        }
        providerConfig.setAuthorizationEndpoint(OAuth2Util.OAuthURL.getOAuth2AuthzEPUrl());
        providerConfig.setPushedAuthorizationRequestEndpoint(OAuth2Util.OAuthURL.getOAuth2ParEPUrl());
        providerConfig.setTokenEndpoint(OAuth2Util.OAuthURL.getOAuth2TokenEPUrl());
        providerConfig.setUserinfoEndpoint(OAuth2Util.OAuthURL.getOAuth2UserInfoEPUrl());
        providerConfig.setRevocationEndpoint(OAuth2Util.OAuthURL.getOAuth2RevocationEPUrl());
        providerConfig.setRevocationEndpointAuthMethodsSupported(OAuth2Util.getSupportedClientAuthenticationMethods()
                .toArray(new String[0]));
        providerConfig.setResponseModesSupported(OAuth2Util.getSupportedResponseModes().toArray(new String[0]));
        providerConfig.setIntrospectionEndpointAuthMethodsSupported(OAuth2Util.getSupportedClientAuthenticationMethods()
                .toArray(new String[0]));
        providerConfig.setCodeChallengeMethodsSupported(OAuth2Util.getSupportedCodeChallengeMethods()
                .toArray(new String[0]));
        try {
            providerConfig.setIntrospectionEndpoint(OAuth2Util.OAuthURL.getOAuth2IntrospectionEPUrl(tenantDomain));
            providerConfig.setRegistrationEndpoint(OAuth2Util.OAuthURL.getOAuth2DCREPUrl(tenantDomain));
            providerConfig.setJwksUri(OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(tenantDomain));
            if (log.isDebugEnabled()) {
                log.debug("Set tenant-specific endpoints for tenant: {}", tenantDomain);
            }
        } catch (URISyntaxException e) {
            log.error("Error while building tenant-specific URLs for tenant: {}", tenantDomain, e);
            throw new ServerConfigurationException("Error while building tenant specific url", e);
        }
        List<String> scopes = OAuth2Util.getOIDCScopes(tenantDomain);
        providerConfig.setScopesSupported(scopes.toArray(new String[scopes.size()]));
        try {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving OIDC claims for tenant: {}", tenantDomain);
            }
            List<ExternalClaim> claims = OIDCDiscoveryDataHolder.getInstance().getClaimManagementService()
                    .getExternalClaims(OIDC_CLAIM_DIALECT, tenantDomain);
            String[] claimArray = new String[claims.size() + 2];
            int i;
            for (i = 0; i < claims.size(); i++) {
                claimArray[i] = claims.get(i).getClaimURI();
            }
            claimArray[i++] = "iss";
            claimArray[i] = "acr";
            providerConfig.setClaimsSupported(claimArray);
            if (log.isDebugEnabled()) {
                log.debug("Successfully set {} claims for OIDC discovery in tenant: {}", claims.size() + 2, tenantDomain);
            }
        } catch (ClaimMetadataException e) {
            log.error("Error while retrieving OIDC claim dialect for tenant: {}", tenantDomain, e);
            throw new ServerConfigurationException("Error while retrieving OIDC claim dialect", e);
        }
        try {
            String signingAlg = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                    OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm()).getName();
            providerConfig.setIdTokenSigningAlgValuesSupported(new String[]{signingAlg});
            if (log.isDebugEnabled()) {
                log.debug("Set ID token signing algorithm: {} for tenant: {}", signingAlg, tenantDomain);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Unsupported signature algorithm configured for ID token in tenant: {}", tenantDomain, e);
            throw new ServerConfigurationException("Unsupported signature algorithm configured.", e);
        }

        Set<String> supportedResponseTypeNames = OAuthServerConfiguration.getInstance().getSupportedResponseTypeNames();
        providerConfig.setResponseTypesSupported(supportedResponseTypeNames.toArray(new
                String[supportedResponseTypeNames.size()]));

        providerConfig.setSubjectTypesSupported(new String[]{"public", "pairwise"});

        providerConfig.setCheckSessionIframe(buildServiceUrl(IdentityConstants.OAuth.CHECK_SESSION,
                IdentityUtil.getProperty(IdentityConstants.OAuth.OIDC_CHECK_SESSION_EP_URL),
                IdentityUtil.getProperty(IdentityConstants.OAuth.OIDC_CHECK_SESSION_EP_URL_V2)));
        providerConfig.setEndSessionEndpoint(buildServiceUrl(IdentityConstants.OAuth.LOGOUT,
                IdentityUtil.getProperty(IdentityConstants.OAuth.OIDC_LOGOUT_EP_URL),
                IdentityUtil.getProperty(IdentityConstants.OAuth.OIDC_LOGOUT_EP_URL_V2)));
        try {
            String userinfoSigningAlg = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                    OAuthServerConfiguration.getInstance().getUserInfoJWTSignatureAlgorithm()).getName();
            providerConfig.setUserinfoSigningAlgValuesSupported(new String[] {userinfoSigningAlg});
            if (log.isDebugEnabled()) {
                log.debug("Set UserInfo signing algorithm: {} for tenant: {}", userinfoSigningAlg, tenantDomain);
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Unsupported signature algorithm configured for UserInfo in tenant: {}", tenantDomain, e);
            throw new ServerConfigurationException("Unsupported signature algorithm configured.", e);
        }

        providerConfig.setTokenEndpointAuthMethodsSupported(OAuth2Util.getSupportedClientAuthMethods());
        providerConfig.setGrantTypesSupported(OAuth2Util.getSupportedGrantTypes().stream().toArray(String[]::new));
        providerConfig.setRequestParameterSupported(Boolean.valueOf(OAuth2Util.isRequestParameterSupported()));
        providerConfig.setClaimsParameterSupported(Boolean.valueOf(OAuth2Util.isClaimsParameterSupported()));
        providerConfig.setRequestObjectSigningAlgValuesSupported(
                OAuth2Util.getRequestObjectSigningAlgValuesSupported().stream().toArray(String[]::new));

        providerConfig.setBackchannelLogoutSupported(Boolean.TRUE);
        providerConfig.setBackchannelLogoutSessionSupported(Boolean.TRUE);

        if (OAuth2Util.getSupportedGrantTypes().contains(DEVICE_FLOW_GRANT_TYPE)) {
            providerConfig.setDeviceAuthorizationEndpoint(OAuth2Util.OAuthURL.getDeviceAuthzEPUrl());
        }
        List<String> supportedTokenEndpointSigningAlgorithms = OAuthServerConfiguration.getInstance()
                .getSupportedTokenEndpointSigningAlgorithms();
        providerConfig.setTokenEndpointAuthSigningAlgValuesSupported(
                supportedTokenEndpointSigningAlgorithms.toArray(new String[0]));
        providerConfig.setWebFingerEndpoint(OAuth2Util.OAuthURL.getOidcWebFingerEPUrl());
        providerConfig.setTlsClientCertificateBoundAccessTokens(OAuth2Util.getSupportedTokenBindingTypes()
                .contains(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER));
        providerConfig.setMtlsTokenEndpoint(OAuth2Util.OAuthURL.getOAuth2MTLSTokenEPUrl());
        providerConfig.setMtlsPushedAuthorizationRequestEndpoint(OAuth2Util.OAuthURL.getOAuth2MTLSParEPUrl());

        final Set<String> authorizationDetailTypes = AuthorizationDetailsProcessorFactory.getInstance()
                .getSupportedAuthorizationDetailTypes();
        if (authorizationDetailTypes != null && !authorizationDetailTypes.isEmpty()) {
            providerConfig
                    .setAuthorizationDetailsTypesSupported(authorizationDetailTypes.stream().toArray(String[]::new));
            if (log.isDebugEnabled()) {
                log.debug("Added {} authorization detail types to OIDC discovery for tenant: {}", 
                        authorizationDetailTypes.size(), tenantDomain);
            }
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Successfully built complete OIDC provider configuration for tenant: {}", tenantDomain);
        }
        return providerConfig;
    }
}
