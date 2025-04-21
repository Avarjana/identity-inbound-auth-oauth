/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.dcr.endpoint.exmapper;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.carbon.identity.oauth.dcr.DCRMConstants;
import org.wso2.carbon.identity.oauth2.dcr.endpoint.dto.ErrorDTO;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Handles exceptions when an incorrect json requests body is received.
 * Sends a default error response.
 */
public class JsonProcessingExceptionMapper implements ExceptionMapper<UnrecognizedPropertyException> {

    private static final Log log = LogFactory.getLog(JsonProcessingExceptionMapper.class);
    private static final Logger LOGGER = LogManager.getLogger(JsonProcessingExceptionMapper.class);

    @Override
    public Response toResponse(UnrecognizedPropertyException e) {

        if (log.isDebugEnabled()) {
            log.debug("Provided JSON request content is not in the valid format:", e);
        }

        // Log the exception with Log4j
        LOGGER.error("Invalid DCR request received with unrecognized field: {}", e.getPropertyName());
        
        ErrorDTO errorDTO = new ErrorDTO();
        String error = DCRMConstants.ErrorCodes.INVALID_CLIENT_METADATA;
        errorDTO.setError(error);
        errorDTO.setErrorDescription(String.format("Unrecognized field : %s", e.getPropertyName()));

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}

