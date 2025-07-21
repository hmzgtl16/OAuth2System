package org.example.oauth2.authorization.repository;

import org.example.oauth2.authorization.model.*;
import org.example.oauth2.authorization.model.OAuth2CodeGrantAuthorization;
import org.example.oauth2.authorization.model.OAuth2GrantAuthorization;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2GrantAuthorizationRepository extends CrudRepository<OAuth2GrantAuthorization, String> {

    <T extends OAuth2CodeGrantAuthorization> T findByState(String state);

    <T extends OAuth2CodeGrantAuthorization> T findByAuthorizationCode_TokenValue(String authorizationCode);

    <T extends OAuth2CodeGrantAuthorization> T findByStateOrAuthorizationCode_TokenValue(String state, String authorizationCode);

    <T extends OAuth2GrantAuthorization> T findByAccessToken_TokenValue(String accessToken);

    <T extends OAuth2GrantAuthorization> T findByRefreshToken_TokenValue(String refreshToken);

    <T extends OAuth2GrantAuthorization> T findByAccessToken_TokenValueOrRefreshToken_TokenValue(String accessToken, String refreshToken);

    <T extends OidcCodeGrantAuthorization> T findByIdToken_TokenValue(String idToken);

    <T extends OAuth2DeviceCodeGrantAuthorization> T findByDeviceState(String deviceState);

    <T extends OAuth2DeviceCodeGrantAuthorization> T findByDeviceCode_TokenValue(String deviceCode);

    <T extends OAuth2DeviceCodeGrantAuthorization> T findByUserCode_TokenValue(String userCode);

    <T extends OAuth2DeviceCodeGrantAuthorization> T findByDeviceStateOrDeviceCode_TokenValueOrUserCode_TokenValue(
            String deviceState,
            String deviceCode,
            String userCode
    );
}