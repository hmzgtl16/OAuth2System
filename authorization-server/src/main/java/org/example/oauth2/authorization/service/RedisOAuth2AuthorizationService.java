package org.example.oauth2.authorization.service;

import org.example.oauth2.authorization.model.OAuth2GrantAuthorization;
import org.example.oauth2.authorization.repository.OAuth2GrantAuthorizationRepository;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final RegisteredClientRepository registeredClientRepository;

    private final OAuth2GrantAuthorizationRepository authorizationGrantAuthorizationRepository;

    public RedisOAuth2AuthorizationService(
            RegisteredClientRepository registeredClientRepository,
            OAuth2GrantAuthorizationRepository oAuth2GrantAuthorizationRepository
    ) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(oAuth2GrantAuthorizationRepository, "oAuth2GrantAuthorizationRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationGrantAuthorizationRepository = oAuth2GrantAuthorizationRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2GrantAuthorization oAuth2GrantAuthorization = ModelMapper
                .convertOAuth2AuthorizationGrantAuthorization(authorization);
        this.authorizationGrantAuthorizationRepository.save(oAuth2GrantAuthorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationGrantAuthorizationRepository.deleteById(authorization.getId());
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizationGrantAuthorizationRepository.findById(id)
                .map(this::toOAuth2Authorization)
                .orElse(null);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        OAuth2GrantAuthorization oAuth2GrantAuthorization = null;
        if (tokenType == null) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByStateOrAuthorizationCode_TokenValue(token, token);
            if (oAuth2GrantAuthorization == null) {
                oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                        .findByAccessToken_TokenValueOrRefreshToken_TokenValue(token, token);
            }
            if (oAuth2GrantAuthorization == null) {
                oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                        .findByIdToken_TokenValue(token);
            }
            if (oAuth2GrantAuthorization == null) {
                oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                        .findByDeviceStateOrDeviceCode_TokenValueOrUserCode_TokenValue(token, token, token);
            }
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository.findByState(token);
            if (oAuth2GrantAuthorization == null) {
                oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                        .findByDeviceState(token);
            }
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByAuthorizationCode_TokenValue(token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByAccessToken_TokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByIdToken_TokenValue(token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByRefreshToken_TokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByUserCode_TokenValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            oAuth2GrantAuthorization = this.authorizationGrantAuthorizationRepository
                    .findByDeviceCode_TokenValue(token);
        }
        return oAuth2GrantAuthorization != null ? toOAuth2Authorization(oAuth2GrantAuthorization) : null;
    }

    private OAuth2Authorization toOAuth2Authorization(
            OAuth2GrantAuthorization oAuth2GrantAuthorization) {
        RegisteredClient registeredClient = this.registeredClientRepository
                .findById(oAuth2GrantAuthorization.getRegisteredClientId());
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient);
        ModelMapper.mapOAuth2AuthorizationGrantAuthorization(oAuth2GrantAuthorization, builder);
        return builder.build();
    }
}