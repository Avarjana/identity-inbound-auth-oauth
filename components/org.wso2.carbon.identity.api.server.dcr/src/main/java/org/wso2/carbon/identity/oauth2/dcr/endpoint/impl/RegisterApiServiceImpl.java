/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.dcr.endpoint.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth.dcr.bean.Application;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMClientException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMServerException;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.RegisterApiService;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ApplicationDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.RegistrationRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.UpdateRequestDTO;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.util.DCRMUtils;

import javax.ws.rs.core.Response;

/**
 * API Service implementation to manage a DCR application.
 */
public class RegisterApiServiceImpl extends RegisterApiService {

    private static final Log LOG = LogFactory.getLog(RegisterApiServiceImpl.class);
    private static final Logger LOGGER = LogManager.getLogger(RegisterApiServiceImpl.class);

    @Override
    public Response deleteApplication(String clientId) {

        try {
            LOGGER.info("Deleting DCR application with client ID: {}", clientId);
            DCRMUtils.getOAuth2DCRMService().deleteApplication(clientId);
            LOGGER.info("Successfully deleted DCR application with client ID: {}", clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while deleting  application with client key:" + clientId, e);
            }
            LOGGER.warn("Failed to delete DCR application. Client error for client ID: {}, Error: {}", 
                clientId, e.getMessage());
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            LOGGER.error("Server error while deleting DCR application with client ID: {}, Error: {}", 
                clientId, e.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);
        } catch (Throwable throwable) {
            LOGGER.error("Unexpected error while deleting DCR application with client ID: {}", 
                clientId, throwable);
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.NO_CONTENT).build();
    }

    @Override
    public Response getApplication(String clientId) {

        ApplicationDTO applicationDTO = null;
        try {
            LOGGER.debug("Retrieving DCR application with client ID: {}", clientId);
            Application application = DCRMUtils.getOAuth2DCRMService().getApplication(clientId);
            applicationDTO = DCRMUtils.getApplicationDTOFromApplication(application);
            LOGGER.debug("Successfully retrieved DCR application with client ID: {}", clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while retrieving  application with client key:" + clientId, e);
            }
            LOGGER.warn("Failed to retrieve DCR application. Client error for client ID: {}, Error: {}", 
                clientId, e.getMessage());
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            LOGGER.error("Server error while retrieving DCR application with client ID: {}, Error: {}", 
                clientId, e.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);
        } catch (Throwable throwable) {
            LOGGER.error("Unexpected error while retrieving DCR application with client ID: {}", 
                clientId, throwable);
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }

    @Override
    public Response registerApplication(RegistrationRequestDTO registrationRequest) {

        if (registrationRequest == null) {
            LOGGER.error("Application registration failed: Registration request is null");
            DCRMException dcrmException = new DCRMException(
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INSUFFICIENT_DATA.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.BAD_REQUEST, dcrmException, false, LOG);
        }

        ApplicationDTO applicationDTO = null;
        try {
            LOGGER.info("Registering new DCR application with name: {}", registrationRequest.getClientName());
            Application application = DCRMUtils.getOAuth2DCRMService()
                    .registerApplication(DCRMUtils.getApplicationRegistrationRequest(registrationRequest));
            applicationDTO = DCRMUtils.getApplicationDTOFromApplication(application);
            LOGGER.info("Successfully registered DCR application. Client ID: {}", applicationDTO.getClientId());
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while registering application \n" + registrationRequest.toString(), e);
            }
            LOGGER.warn("Failed to register DCR application with name: {}. Error: {}", 
                registrationRequest.getClientName(), e.getMessage());
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            LOGGER.error("Server error while registering DCR application with name: {}. Error: {}", 
                registrationRequest.getClientName(), e.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);
        } catch (Throwable throwable) {
            LOGGER.error("Unexpected error while registering DCR application with name: {}", 
                registrationRequest.getClientName(), throwable);
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.CREATED).entity(applicationDTO).build();
    }

    @Override
    public Response updateApplication(UpdateRequestDTO updateRequest, String clientId) {

        if (updateRequest == null) {
            LOGGER.error("Application update failed: Update request is null for client ID: {}", clientId);
            DCRMException dcrmException = new DCRMException(
                    DCRMConstants.ErrorMessages.BAD_REQUEST_INSUFFICIENT_DATA.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.BAD_REQUEST, dcrmException, false, LOG);
        }

        ApplicationDTO applicationDTO = null;
        try {
            LOGGER.info("Updating DCR application with client ID: {}", clientId);
            Application application = DCRMUtils.getOAuth2DCRMService()
                    .updateApplication(DCRMUtils.getApplicationUpdateRequest(updateRequest), clientId);
            applicationDTO = DCRMUtils.getApplicationDTOFromApplication(application);
            LOGGER.info("Successfully updated DCR application with client ID: {}", clientId);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while updating application \n" + updateRequest.toString(), e);
            }
            LOGGER.warn("Failed to update DCR application with client ID: {}. Error: {}", 
                clientId, e.getMessage());
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (DCRMServerException e) {
            LOGGER.error("Server error while updating DCR application with client ID: {}. Error: {}", 
                clientId, e.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);
        } catch (Throwable throwable) {
            LOGGER.error("Unexpected error while updating DCR application with client ID: {}", 
                clientId, throwable);
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, throwable, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }

    @Override
    public Response getApplicationByName(String name) {

        ApplicationDTO applicationDTO = null;
        try {
            LOGGER.debug("Retrieving DCR application by name: {}", name);
            Application application = DCRMUtils.getOAuth2DCRMService().getApplicationByName(name);
            applicationDTO = DCRMUtils.getApplicationDTOFromApplication(application);
            LOGGER.debug("Successfully retrieved DCR application by name: {}", name);
        } catch (DCRMClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Client error while retrieving application by name : " + name, e);
            }
            LOGGER.warn("Failed to retrieve DCR application by name: {}. Error: {}", name, e.getMessage());
            DCRMUtils.handleErrorResponse(e, LOG);
        } catch (Exception e) {
            LOGGER.error("Error while retrieving DCR application by name: {}. Error: {}", name, e.getMessage());
            DCRMUtils.handleErrorResponse(Response.Status.INTERNAL_SERVER_ERROR, e, true, LOG);
        }
        return Response.status(Response.Status.OK).entity(applicationDTO).build();
    }
}
