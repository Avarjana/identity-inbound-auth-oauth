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
            log.debug("Building OIDC provider configuration for tenant domain: {}", request.getTenantDomain());
        }
        OIDProviderConfigResponse providerConfig = new OIDProviderConfigResponse();
        String tenantDomain = request.getTenantDomain();
        if (isUseEntityIdAsIssuerInOidcDiscovery()) {
            try {
                String idTokenIssuer = OAuth2Util.getIdTokenIssuer(tenantDomain);
                providerConfig.setIssuer(idTokenIssuer);
                if (log.isDebugEnabled()) {
                    log.debug("Using entity ID as issuer: {}", idTokenIssuer);
                }
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = String.format("Error while retrieving OIDC Id token issuer value for tenant domain: %s", 
                        tenantDomain);
                log.error(errorMsg, e);
                throw new ServerConfigurationException(errorMsg, e);
            }
        } else {
            String idTokenIssuer = OAuth2Util.getIDTokenIssuer();
            providerConfig.setIssuer(idTokenIssuer);
            if (log.isDebugEnabled()) {
                log.debug("Using default issuer: {}", idTokenIssuer);
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
            String introspectionEndpoint = OAuth2Util.OAuthURL.getOAuth2IntrospectionEPUrl(tenantDomain);
            String registrationEndpoint = OAuth2Util.OAuthURL.getOAuth2DCREPUrl(tenantDomain);
            String jwksUri = OAuth2Util.OAuthURL.getOAuth2JWKSPageUrl(tenantDomain);
            
            providerConfig.setIntrospectionEndpoint(introspectionEndpoint);
            providerConfig.setRegistrationEndpoint(registrationEndpoint);
            providerConfig.setJwksUri(jwksUri);
            
            if (log.isDebugEnabled()) {
                log.debug("Set tenant-specific endpoints - Introspection: {}, Registration: {}, JWKS URI: {}",
                        introspectionEndpoint, registrationEndpoint, jwksUri);
            }
        } catch (URISyntaxException e) {
            String errorMsg = "Error while building tenant specific URLs for tenant: " + tenantDomain;
            log.error(errorMsg, e);
            throw new ServerConfigurationException(errorMsg, e);
        }
        List<String> scopes = OAuth2Util.getOIDCScopes(tenantDomain);
        providerConfig.setScopesSupported(scopes.toArray(new String[scopes.size()]));
        try {
            List<ExternalClaim> claims = OIDCDiscoveryDataHolder.getInstance().getClaimManagementService()
                    .getExternalClaims(OIDC_CLAIM_DIALECT, tenantDomain);
            
            if (log.isDebugEnabled()) {
                log.debug("Retrieved {} OIDC claims for tenant domain: {}", claims.size(), tenantDomain);
            }
            
            String[] claimArray = new String[claims.size() + 2];
            int i;
            for (i = 0; i < claims.size(); i++) {
                claimArray[i] = claims.get(i).getClaimURI();
            }
            claimArray[i++] = "iss";
            claimArray[i] = "acr";
            providerConfig.setClaimsSupported(claimArray);
        } catch (ClaimMetadataException e) {
            String errorMsg = "Error while retrieving OIDC claim dialect for tenant: " + tenantDomain;
            log.error(errorMsg, e);
            throw new ServerConfigurationException(errorMsg, e);
        }
        try {
            String sigAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                    OAuthServerConfiguration.getInstance().getIdTokenSignatureAlgorithm()).getName();
            providerConfig.setIdTokenSigningAlgValuesSupported(new String[]{ sigAlgorithm });
            
            if (log.isDebugEnabled()) {
                log.debug("ID token signing algorithm: {}", sigAlgorithm);
            }
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Unsupported signature algorithm configured for ID token";
            log.error(errorMsg, e);
            throw new ServerConfigurationException(errorMsg, e);
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
            String userInfoSigningAlg = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(
                    OAuthServerConfiguration.getInstance().getUserInfoJWTSignatureAlgorithm()).getName();
            providerConfig.setUserinfoSigningAlgValuesSupported(new String[] { userInfoSigningAlg });
            
            if (log.isDebugEnabled()) {
                log.debug("UserInfo JWT signing algorithm: {}", userInfoSigningAlg);
            }
        } catch (IdentityOAuth2Exception e) {
            String errorMsg = "Unsupported signature algorithm configured for UserInfo JWT";
            log.error(errorMsg, e);
            throw new ServerConfigurationException(errorMsg, e);
        }

        providerConfig.setTokenEndpointAuthMethodsSupported(OAuth2Util.getSupportedClientAuthMethods());
        providerConfig.setGrantTypesSupported(OAuth2Util.getSupportedGrantTypes().stream().toArray(String[]::new));
        providerConfig.setRequestParameterSupported(Boolean.valueOf(OAuth2Util.isRequestParameterSupported()));
        providerConfig.setClaimsParameterSupported(Boolean.valueOf(OAuth2Util.isClaimsParameterSupported()));
        providerConfig.setRequestObjectSigningAlgValuesSupported(
                OAuth2Util.getRequestObjectSigningAlgValuesSupported().stream().toArray(String[]::new));

        providerConfig.setBackchannelLogoutSupported(Boolean.TRUE);
        providerConfig.setBackchannelLogoutSessionSupported(Boolean.TRUE);

        boolean supportsDeviceFlow = OAuth2Util.getSupportedGrantTypes().contains(DEVICE_FLOW_GRANT_TYPE);
        if (supportsDeviceFlow) {
            String deviceAuthzEndpoint = OAuth2Util.OAuthURL.getDeviceAuthzEPUrl();
            providerConfig.setDeviceAuthorizationEndpoint(deviceAuthzEndpoint);
            if (log.isDebugEnabled()) {
                log.debug("Device flow grant type is supported, device authorization endpoint: {}", deviceAuthzEndpoint);
            }
        } else if (log.isDebugEnabled()) {
            log.debug("Device flow grant type is not supported");
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
            String[] typesArray = authorizationDetailTypes.stream().toArray(String[]::new);
            providerConfig.setAuthorizationDetailsTypesSupported(typesArray);
            
            if (log.isDebugEnabled()) {
                log.debug("Authorization details types supported: {}", String.join(", ", authorizationDetailTypes));
            }
        } else if (log.isDebugEnabled()) {
            log.debug("No authorization details types are supported");
        }
        
        if (log.isDebugEnabled()) {
            log.debug("Successfully built OIDC provider configuration for tenant: {}", tenantDomain);
        }
        return providerConfig;
    }
}
