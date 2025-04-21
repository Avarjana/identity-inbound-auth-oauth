/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.rar.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.rar.dto.AuthorizationDetailsCodeDTO;
import org.wso2.carbon.identity.oauth.rar.dto.AuthorizationDetailsConsentDTO;
import org.wso2.carbon.identity.oauth.rar.dto.AuthorizationDetailsTokenDTO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

/**
 * Implements the {@link AuthorizationDetailsDAO} interface to manage rich authorization requests.
 *
 * <p> {@link AuthorizationDetailsDAO} provides methods to add, update, retrieve, and delete authorization details
 * associated with user consent and access tokens.
 */
public class AuthorizationDetailsDAOImpl implements AuthorizationDetailsDAO {

    private static final Log log = LogFactory.getLog(AuthorizationDetailsDAOImpl.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] addUserConsentedAuthorizationDetails(final Set<AuthorizationDetailsConsentDTO> consentDTOs)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Adding user consented authorization details. Count: {}", consentDTOs.size());
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsConsentDTO consentDTO : consentDTOs) {
                ps.setString(1, consentDTO.getConsentId());
                ps.setString(2, consentDTO.getAuthorizationDetail().toJsonString());
                ps.setBoolean(3, consentDTO.isConsentActive());
                ps.setString(4, consentDTO.getAuthorizationDetail().getType());
                ps.setInt(5, consentDTO.getTenantId());
                ps.setInt(6, consentDTO.getTenantId());
                ps.addBatch();
            }
            int[] result = ps.executeBatch();
            log.info("Successfully added user consented authorization details");
            return result;
        } catch (SQLException e) {
            log.error("Error while adding user consented authorization details", e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] updateUserConsentedAuthorizationDetails(final Set<AuthorizationDetailsConsentDTO> consentDTOs)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Updating user consented authorization details. Count: {}", consentDTOs.size());
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.UPDATE_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsConsentDTO consentDTO : consentDTOs) {
                ps.setString(1, consentDTO.getAuthorizationDetail().toJsonString());
                ps.setBoolean(2, consentDTO.isConsentActive());
                ps.setString(3, consentDTO.getConsentId());
                ps.setString(4, consentDTO.getAuthorizationDetail().getType());
                ps.setInt(5, consentDTO.getTenantId());
                ps.setInt(6, consentDTO.getTenantId());
                ps.addBatch();
            }
            int[] result = ps.executeBatch();
            log.info("Successfully updated user consented authorization details");
            return result;
        } catch (SQLException e) {
            log.error("Error while updating user consented authorization details", e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<AuthorizationDetailsConsentDTO> getUserConsentedAuthorizationDetails(final String consentId,
                                                                                    final int tenantId)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving user consented authorization details for consentId: {}, tenantId: {}", 
                    consentId, tenantId);
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            ps.setString(1, consentId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {

                final Set<AuthorizationDetailsConsentDTO> authorizationDetailsConsentDTOs = new HashSet<>();
                while (rs.next()) {
                    final String id = rs.getString(1);
                    final String typeId = rs.getString(2);
                    final String authorizationDetail = rs.getString(3);
                    final boolean isConsentActive = rs.getBoolean(4);

                    authorizationDetailsConsentDTOs.add(new AuthorizationDetailsConsentDTO(id, consentId, typeId,
                            authorizationDetail, isConsentActive, tenantId));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved {} user consented authorization details", 
                            authorizationDetailsConsentDTOs.size());
                }
                return authorizationDetailsConsentDTOs;
            }
        } catch (SQLException e) {
            log.error("Error while retrieving user consented authorization details for consentId: {}", consentId, e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int deleteUserConsentedAuthorizationDetails(final String consentId, final int tenantId)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting user consented authorization details for consentId: {}, tenantId: {}", 
                    consentId, tenantId);
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.DELETE_OAUTH2_USER_CONSENTED_AUTHORIZATION_DETAILS)) {

            ps.setString(1, consentId);
            ps.setInt(2, tenantId);
            int rowsAffected = ps.executeUpdate();
            log.info("Deleted {} user consented authorization details for consentId: {}", rowsAffected, consentId);
            return rowsAffected;
        } catch (SQLException e) {
            log.error("Error while deleting user consented authorization details for consentId: {}", consentId, e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] addAccessTokenAuthorizationDetails(final Set<AuthorizationDetailsTokenDTO> tokenDTOs)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Adding access token authorization details. Count: {}", tokenDTOs.size());
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsTokenDTO tokenDTO : tokenDTOs) {
                ps.setString(1, tokenDTO.getAccessTokenId());
                ps.setString(2, tokenDTO.getAuthorizationDetail().toJsonString());
                ps.setString(3, tokenDTO.getAuthorizationDetail().getType());
                ps.setInt(4, tokenDTO.getTenantId());
                ps.setInt(5, tokenDTO.getTenantId());
                ps.addBatch();
            }
            int[] result = ps.executeBatch();
            log.info("Successfully added access token authorization details");
            return result;
        } catch (SQLException e) {
            log.error("Error while adding access token authorization details", e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<AuthorizationDetailsTokenDTO> getAccessTokenAuthorizationDetails(final String accessTokenId,
                                                                                final int tenantId)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving access token authorization details for accessTokenId: {}, tenantId: {}", 
                     accessTokenId, tenantId);
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS)) {

            ps.setString(1, accessTokenId);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {

                final Set<AuthorizationDetailsTokenDTO> authorizationDetailsTokenDTO = new HashSet<>();
                while (rs.next()) {
                    final String id = rs.getString(1);
                    final String typeId = rs.getString(2);
                    final String authorizationDetail = rs.getString(3);

                    authorizationDetailsTokenDTO.add(
                            new AuthorizationDetailsTokenDTO(id, accessTokenId, typeId, authorizationDetail, tenantId));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved {} access token authorization details", authorizationDetailsTokenDTO.size());
                }
                return authorizationDetailsTokenDTO;
            }
        } catch (SQLException e) {
            log.error("Error while retrieving access token authorization details for accessTokenId: {}", 
                     accessTokenId, e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int deleteAccessTokenAuthorizationDetails(final String accessTokenId, final int tenantId)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Deleting access token authorization details for accessTokenId: {}, tenantId: {}", 
                     accessTokenId, tenantId);
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.DELETE_OAUTH2_ACCESS_TOKEN_AUTHORIZATION_DETAILS)) {

            ps.setString(1, accessTokenId);
            ps.setInt(2, tenantId);
            int rowsAffected = ps.executeUpdate();
            log.info("Deleted {} access token authorization details for accessTokenId: {}", rowsAffected, accessTokenId);
            return rowsAffected;
        } catch (SQLException e) {
            log.error("Error while deleting access token authorization details for accessTokenId: {}", 
                     accessTokenId, e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int[] addOAuth2CodeAuthorizationDetails(final Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Adding OAuth2 code authorization details. Count: {}", authorizationDetailsCodeDTOs.size());
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.ADD_OAUTH2_CODE_AUTHORIZATION_DETAILS)) {

            for (AuthorizationDetailsCodeDTO authorizationDetailsCodeDTO : authorizationDetailsCodeDTOs) {
                ps.setString(1, authorizationDetailsCodeDTO.getAuthorizationCodeId());
                ps.setString(2, authorizationDetailsCodeDTO.getAuthorizationDetail().toJsonString());
                ps.setString(3, authorizationDetailsCodeDTO.getAuthorizationDetail().getType());
                ps.setInt(4, authorizationDetailsCodeDTO.getTenantId());
                ps.setInt(5, authorizationDetailsCodeDTO.getTenantId());
                ps.addBatch();
            }
            int[] result = ps.executeBatch();
            log.info("Successfully added OAuth2 code authorization details");
            return result;
        } catch (SQLException e) {
            log.error("Error while adding OAuth2 code authorization details", e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<AuthorizationDetailsCodeDTO> getOAuth2CodeAuthorizationDetails(final String authorizationCode,
                                                                              final int tenantId) throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving OAuth2 code authorization details for authorizationCode: {}, tenantId: {}", 
                    authorizationCode, tenantId);
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_OAUTH2_CODE_AUTHORIZATION_DETAILS_BY_CODE)) {

            ps.setString(1, authorizationCode);
            ps.setInt(2, tenantId);
            try (ResultSet rs = ps.executeQuery()) {

                final Set<AuthorizationDetailsCodeDTO> authorizationDetailsCodeDTOs = new HashSet<>();
                while (rs.next()) {
                    final String codeId = rs.getString(1);
                    final String typeId = rs.getString(2);
                    final String authorizationDetail = rs.getString(3);

                    authorizationDetailsCodeDTOs.add(new AuthorizationDetailsCodeDTO(
                            codeId, typeId, authorizationDetail, tenantId));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved {} OAuth2 code authorization details", authorizationDetailsCodeDTOs.size());
                }
                return authorizationDetailsCodeDTOs;
            }
        } catch (SQLException e) {
            log.error("Error while retrieving OAuth2 code authorization details for authorizationCode: {}", 
                    authorizationCode, e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getConsentIdByUserIdAndAppId(final String userId, final String appId, final int tenantId)
            throws SQLException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving consent ID for userId: {}, appId: {}, tenantId: {}", userId, appId, tenantId);
        }
        try (final Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             final PreparedStatement ps =
                     connection.prepareStatement(SQLQueries.GET_IDN_OAUTH2_USER_CONSENT_CONSENT_ID)) {

            ps.setString(1, userId);
            ps.setString(2, appId);
            ps.setInt(3, tenantId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String consentId = rs.getString(1);
                    if (log.isDebugEnabled()) {
                        log.debug("Found consent ID: {} for userId: {}, appId: {}", consentId, userId, appId);
                    }
                    return consentId;
                }
            }
        } catch (SQLException e) {
            log.error("Error while retrieving consent ID for userId: {}, appId: {}", userId, appId, e);
            throw e;
        }
        if (log.isDebugEnabled()) {
            log.debug("No consent ID found for userId: {}, appId: {}", userId, appId);
        }
        return null;
    }
}
