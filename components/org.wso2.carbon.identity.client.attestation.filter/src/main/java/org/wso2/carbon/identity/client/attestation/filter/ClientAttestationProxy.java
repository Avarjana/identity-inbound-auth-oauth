/*
 *  Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.client.attestation.filter;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.impl.MetadataMap;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementClientException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.client.attestation.mgt.exceptions.ClientAttestationMgtException;
import org.wso2.carbon.identity.client.attestation.mgt.model.ClientAttestationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.ATTESTATION_HEADER;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.CLIENT_ATTESTATION_CONTEXT;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.DIRECT;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.OAUTH2;
import static org.wso2.carbon.identity.client.attestation.mgt.utils.Constants.RESPONSE_MODE;

/**
 * This interceptor, ClientAttestationProxy, is responsible for handling incoming JAX-RS messages related to
 * client attestation. It checks for attestation information in the HTTP request and validates it to establish
 * the client's authenticity and context.
 * It operates at the "PRE_INVOKE" phase, allowing it to access the message body and parameters.
 * The interceptor performs the following tasks:
 * 1. Extracts the HttpServletRequest from the incoming JAX-RS message.
 * 2. Retrieves the attestation header from the HTTP request.
 * 3. Extracts content parameters from the message.
 * 4. Validates attestation for API-based authentication requests.
 * 5. Sets the client attestation context in the HTTP request for further processing.
 *
 */
public class ClientAttestationProxy extends AbstractPhaseInterceptor<Message> {

    private static final Log LOG = LogFactory.getLog(ClientAttestationProxy.class);
    private static final String HTTP_REQUEST = "HTTP.REQUEST";
    private static final String AUTHZ_ENDPOINT_PATH = "/oauth2/authorize";
    private static final String CLIENT_ID = "client_id";
    private static final String ERROR = "error";
    private static final String ERROR_DESCRIPTION = "error_description";
    private static final String SLASH = "/";

    public ClientAttestationProxy() {

        // Since the body is consumed and body parameters are available at this phase we use "PRE_INVOKE"
        super(Phase.PRE_INVOKE);
    }

    /**
     * Handles the incoming JAX-RS message for the purpose of OAuth2 client authentication.
     * It extracts the HttpServletRequest from the incoming message, retrieves the attestation header
     * from the HTTP request, and extracts content parameters from the message.
     * If the incoming request is determined to be an API-based authentication request, it proceeds to:
     * 1. Validate the attestation header to establish client authenticity and obtain a client
     *    attestation context.
     * 2. Set the client attestation context in the HTTP request for further processing.
     *
     * @param message JAX-RS message
     */
    @Override
    public void handleMessage(Message message) {

        // Extract the HttpServletRequest from the incoming message
        HttpServletRequest request = (HttpServletRequest) message.get(HTTP_REQUEST);
        // Retrieve the attestation header from the HTTP request
        String attestationHeader = request.getHeader(ATTESTATION_HEADER);
        // Extract the content parameters from the message
        Map<String, List> bodyContentParams = getContentParams(message);

        // Check if this is an API-based authentication request
        if (canHandle(request, message, bodyContentParams)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Processing client attestation for request path: {}", message.get(Message.REQUEST_URI));
            }

            String clientId = extractClientId(request, bodyContentParams);

            if (StringUtils.isEmpty(clientId)) {
                LOG.error("Client ID not found in the authentication request");
                throw new WebApplicationException(buildResponse("Client Id not found in the request",
                        Response.Status.BAD_REQUEST));
            } else {
                try {
                    String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Retrieving service provider for client ID: {} in tenant: {}", clientId, tenantDomain);
                    }
                    
                    ServiceProvider serviceProvider = getServiceProvider(clientId, tenantDomain);
                    ClientAttestationContext clientAttestationContext;
                    // Attestation validation should be performed only if API-based authentication is enabled.
                    if (serviceProvider.isAPIBasedAuthenticationEnabled()) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("API-based authentication is enabled for application with client ID: {}", clientId);
                        }
                        
                        // Validate the attestation header and obtain client attestation context
                        clientAttestationContext = ClientAttestationServiceHolder
                                .getClientAttestationService().validateAttestation(attestationHeader,
                                        serviceProvider.getApplicationResourceId(),
                                        tenantDomain);
                        
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Attestation validation completed for client ID: {}, attested: {}", 
                                    clientId, clientAttestationContext.isAttested());
                        }
                    } else {
                        /* In order for client attestation to be enabled it requires API-based authentication to be
                         enabled. Therefore, if API-based authentication is disabled, client attestation is disabled.*/
                        LOG.info("API-based authentication is disabled for client ID: {}. Skipping attestation validation.", clientId);
                        clientAttestationContext = new ClientAttestationContext(false);
                        clientAttestationContext.setAttested(false);
                    }
                    // Set the client attestation context in the HTTP request.
                    setContextToRequest(request, clientAttestationContext);
                } catch (ClientAttestationMgtException e) {
                    LOG.error("Error during client attestation validation for client ID: {}", clientId, e);
                    // Create a Response object with a 400 status code and a detailed message
                    Response response = Response
                            .status(Response.Status.BAD_REQUEST)
                            .entity("Invalid Request: " + e.getMessage())
                            .build();

                    // Throw a WebApplicationException with the custom response
                    throw new WebApplicationException(e, response);
                }
            }
        }
    }

    /**
     * Determines whether the interceptor can handle the request based on the request path and the authentication
     * request type.
     *
     * @param message           The CXF Message object representing the incoming request.
     * @return True if the interceptor can handle the request, false otherwise.
     */
    private boolean canHandle(HttpServletRequest request, Message message, Map<String, List> bodyContentParams) {
        boolean matchesEndpoint = isMatchesEndPoint(message);
        boolean isApiBasedAuth = isApiBasedAuthnRequest(request, bodyContentParams);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Request evaluation - Matches endpoint: {}, API-based authentication: {}", 
                    matchesEndpoint, isApiBasedAuth);
        }
        
        return matchesEndpoint && isApiBasedAuth;
    }

    /**
     * Checks if the request path matches the expected authorization endpoint path.
     *
     * @param message The CXF Message object representing the incoming request.
     * @return True if the request path matches the authorization endpoint path, false otherwise.
     */
    private boolean isMatchesEndPoint(Message message) {
        String requestPath = (String) message.get(Message.REQUEST_URI);
        String normalizedPath = removeTrailingSlash(requestPath);
        
        boolean matches = StringUtils.equalsIgnoreCase(normalizedPath, AUTHZ_ENDPOINT_PATH);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Endpoint matching - Request path: {}, Normalized path: {}, Matches authorization endpoint: {}", 
                    requestPath, normalizedPath, matches);
        }
        
        return matches;
    }


    /**
     * Checks if the authentication request is based on API by examining the 'response_mode' parameter.
     * If the 'response_mode' parameter is present in the parsed body content parameters and its value
     * is equal to 'direct', it indicates an API-based authentication request.
     * Otherwise, it checks the 'response_mode' parameter in the request parameters using 'direct' as the default.
     *
     * @param request           The HttpServletRequest object representing the incoming HTTP request.
     * @param bodyContentParams A map containing the parsed parameters from the request body content.
     * @return True if the authentication request is API-based, false otherwise.
     */
    private boolean isApiBasedAuthnRequest(HttpServletRequest request, Map<String, List> bodyContentParams) {
        boolean isApiBasedAuth = false;
        String responseMode = null;
        boolean fromBodyParams = false;
        
        // Check if the 'response_mode' parameter is present in the parsed body content parameters.
        if (bodyContentParams.containsKey(RESPONSE_MODE) && !bodyContentParams.get(RESPONSE_MODE).isEmpty()) {
            // Retrieve the 'response_mode' parameter value from the request body.
            responseMode = bodyContentParams.get(RESPONSE_MODE).get(0).toString();
            fromBodyParams = true;
            // Check if the 'response_mode' parameter value is equal to 'direct'.
            isApiBasedAuth = responseMode.equalsIgnoreCase(DIRECT);
        } else {
            // If 'response_mode' is not found in the body content parameters, fall back to the request parameters.
            responseMode = request.getParameter(RESPONSE_MODE);
            // Check if the 'response_mode' parameter value in the request is equal to 'direct'.
            isApiBasedAuth = StringUtils.equals(DIRECT, responseMode);
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("API-based authentication check - Response mode: {}, Source: {}, Is API-based: {}", 
                    responseMode, fromBodyParams ? "body parameters" : "request parameters", isApiBasedAuth);
        }
        
        return isApiBasedAuth;
    }

    /**
     * Extracts the client ID from the request. It first checks the body content parameters,
     * and if the 'client_id' parameter is found, it returns its value. Otherwise, it falls back
     * to checking the request parameters using the 'response_mode' parameter as a default.
     *
     * @param request           The HttpServletRequest object representing the incoming HTTP request.
     * @param bodyContentParams A map containing the parsed parameters from the request body content.
     * @return The extracted client ID.
     */
    private String extractClientId(HttpServletRequest request, Map<String, List> bodyContentParams) {
        String clientId = null;
        String source = null;
        
        // Check if the 'client_id' parameter is present in the parsed body content parameters.
        if (bodyContentParams.containsKey(CLIENT_ID) && !bodyContentParams.get(CLIENT_ID).isEmpty()) {
            // Retrieve and return the 'client_id' parameter value from the request body.
            clientId = bodyContentParams.get(CLIENT_ID).get(0).toString();
            source = "body parameters";
        } else {
            // If 'client_id' is not found in the body content parameters, fall back to the request parameters.
            // Return the value of the 'client_id' parameter as a default.
            clientId = request.getParameter(CLIENT_ID);
            source = "request parameters";
        }
        
        if (LOG.isDebugEnabled()) {
            if (clientId != null) {
                LOG.debug("Client ID extracted from {}: {}", source, clientId);
            } else {
                LOG.debug("Client ID not found in request");
            }
        }
        
        return clientId;
    }


    /**
     * Retrieve body content as a String, List map.
     *
     * @param message JAX-RS incoming message
     * @return Body parameter of the incoming request message
     */
    protected Map<String, List> getContentParams(Message message) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracting content parameters from JAX-RS message");
        }
        
        Map<String, List> contentMap = new HashMap<>();
        List contentList = message.getContent(List.class);
        
        if (contentList == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No content list found in message");
            }
            return contentMap;
        }
        
        contentList.forEach(item -> {
            if (item instanceof MetadataMap) {
                MetadataMap metadataMap = (MetadataMap) item;
                metadataMap.forEach((key, value) -> {
                    if (key instanceof String && value instanceof List) {
                        contentMap.put((String) key, (List) value);
                    }
                });
            }
        });
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracted {} content parameters from request", contentMap.size());
        }
        
        return contentMap;
    }

    /**
     * Sets the Client Attestation context to the HttpServletRequest's attributes.
     *
     * @param request                   The HttpServletRequest to which the context should be added.
     * @param clientAttestationContext  The Client Attestation context to be added to the request.
     */
    private void setContextToRequest(HttpServletRequest request, ClientAttestationContext clientAttestationContext) {
        if (request == null) {
            LOG.error("Cannot set Client Attestation context: request is null");
            return;
        }
        
        if (clientAttestationContext == null) {
            LOG.error("Cannot set Client Attestation context: context is null");
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting Client Attestation context to request. Attested: {}", 
                    clientAttestationContext.isAttested());
        }
        
        // Add the Client Attestation context as an attribute to the HttpServletRequest
        request.setAttribute(CLIENT_ATTESTATION_CONTEXT, clientAttestationContext);
    }

    /**
     * Retrieves the service provider based on the given client ID and tenant domain.
     *
     * @param clientId     The client ID associated with the service provider.
     * @param tenantDomain The tenant domain in which the service provider is registered.
     * @return The retrieved service provider.
     * @throws WebApplicationException If an error occurs during the retrieval process.
     */
    private ServiceProvider getServiceProvider(String clientId, String tenantDomain) {

        ServiceProvider serviceProvider;
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Retrieving service provider by client ID: {} in tenant: {}", clientId, tenantDomain);
            }
            serviceProvider = ClientAttestationServiceHolder.getApplicationManagementService()
                    .getServiceProviderByClientId(clientId, OAUTH2, tenantDomain);
        } catch (IdentityApplicationManagementClientException e) {
            LOG.error("Invalid client ID: {} in tenant: {}. Error: {}", clientId, tenantDomain, e.getMessage());
            throw new WebApplicationException(
                    buildResponse("Invalid client Id : " + clientId,
                            Response.Status.BAD_REQUEST));
        } catch (IdentityApplicationManagementException e) {
            LOG.error("Error retrieving service provider for client ID: {} in tenant: {}", clientId, tenantDomain, e);
            throw new WebApplicationException(
                        buildResponse("Internal Server Error when retrieving service provider.",
                                Response.Status.INTERNAL_SERVER_ERROR));
        }
        if (serviceProvider == null) {
            LOG.warn("No service provider found for client ID: {} in tenant: {}", clientId, tenantDomain);
            throw new WebApplicationException(buildResponse("Service provider not found.",
                    Response.Status.BAD_REQUEST));
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully retrieved service provider for client ID: {} in tenant: {}", clientId, tenantDomain);
        }
        return serviceProvider;
    }

    /**
     * Builds a JAX-RS Response object with the specified error description and HTTP status.
     *
     * @param errorDescription The description of the error.
     * @param status           The HTTP status to be set in the response.
     * @return A JAX-RS Response object representing the error.
     */
    private Response buildResponse(String errorDescription, Response.Status status) {
        LOG.warn("Building error response - Status: {}, Description: {}", status, errorDescription);

        String errorJSON = new JSONObject().put(ERROR_DESCRIPTION, errorDescription)
                .put(ERROR, status.getReasonPhrase()).toString();

        return Response.status(status).entity(errorJSON).build();
    }

    private String removeTrailingSlash(String url) {
        if (url == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("URL is null when attempting to remove trailing slash");
            }
            return null;
        }
        
        if (url.endsWith(SLASH)) {
            String result = url.substring(0, url.length() - 1);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Removed trailing slash from URL: {} -> {}", url, result);
            }
            return result;
        }
        return url;
    }
}
