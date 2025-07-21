package org.example.oauth2.authorization.service;

import org.example.oauth2.authorization.model.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.security.Principal;

final class ModelMapper {

    static OAuth2RegisteredClient convertOAuth2RegisteredClient(RegisteredClient registeredClient) {
        OAuth2RegisteredClient.ClientSettings clientSettings = new OAuth2RegisteredClient.ClientSettings(
                registeredClient.getClientSettings().isRequireProofKey(),
                registeredClient.getClientSettings().isRequireAuthorizationConsent(),
                registeredClient.getClientSettings().getJwkSetUrl(),
                registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm(),
                registeredClient.getClientSettings().getX509CertificateSubjectDN()
        );

        OAuth2RegisteredClient.TokenSettings tokenSettings = new OAuth2RegisteredClient.TokenSettings(
                registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive(),
                registeredClient.getTokenSettings().getAccessTokenTimeToLive(),
                registeredClient.getTokenSettings().getAccessTokenFormat(),
                registeredClient.getTokenSettings().getDeviceCodeTimeToLive(),
                registeredClient.getTokenSettings().isReuseRefreshTokens(),
                registeredClient.getTokenSettings().getRefreshTokenTimeToLive(),
                registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm(),
                registeredClient.getTokenSettings().isX509CertificateBoundAccessTokens()
        );

        return new OAuth2RegisteredClient(
                registeredClient.getId(),
                registeredClient.getClientId(),
                registeredClient.getClientIdIssuedAt(),
                registeredClient.getClientSecret(),
                registeredClient.getClientSecretExpiresAt(),
                registeredClient.getClientName(),
                registeredClient.getClientAuthenticationMethods(),
                registeredClient.getAuthorizationGrantTypes(),
                registeredClient.getRedirectUris(),
                registeredClient.getPostLogoutRedirectUris(),
                registeredClient.getScopes(),
                clientSettings,
                tokenSettings
        );
    }

    static OAuth2AuthorizationConsent convertOAuth2UserConsent(
            org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent OAuth2AuthorizationConsent
    ) {
        String id = OAuth2AuthorizationConsent.getRegisteredClientId()
                .concat("-")
                .concat(OAuth2AuthorizationConsent.getPrincipalName());
        return new OAuth2AuthorizationConsent(
                id,
                OAuth2AuthorizationConsent.getRegisteredClientId(),
                OAuth2AuthorizationConsent.getPrincipalName(),
                OAuth2AuthorizationConsent.getAuthorities()
        );
    }

    static OAuth2GrantAuthorization convertOAuth2AuthorizationGrantAuthorization(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(OAuth2Authorization.getAuthorizationGrantType())) {
            OAuth2AuthorizationRequest authorizationRequest = OAuth2Authorization
                    .getAttribute(OAuth2AuthorizationRequest.class.getName());
            return authorizationRequest.getScopes().contains(OidcScopes.OPENID)
                    ? convertOidcAuthorizationCodeGrantAuthorization(OAuth2Authorization)
                    : convertOAuth2AuthorizationCodeGrantAuthorization(OAuth2Authorization);
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(OAuth2Authorization.getAuthorizationGrantType())) {
            return convertOAuth2ClientCredentialsGrantAuthorization(OAuth2Authorization);
        } else if (AuthorizationGrantType.DEVICE_CODE.equals(OAuth2Authorization.getAuthorizationGrantType())) {
            return convertOAuth2DeviceCodeGrantAuthorization(OAuth2Authorization);
        } else if (AuthorizationGrantType.TOKEN_EXCHANGE.equals(OAuth2Authorization.getAuthorizationGrantType())) {
            return convertOAuth2TokenExchangeGrantAuthorization(OAuth2Authorization);
        }
        return null;
    }

    static OidcCodeGrantAuthorization convertOidcAuthorizationCodeGrantAuthorization(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2CodeGrantAuthorization.AuthorizationCode authorizationCode =
                extractAuthorizationCode(OAuth2Authorization);
        OAuth2GrantAuthorization.AccessToken accessToken = extractAccessToken(OAuth2Authorization);
        OAuth2GrantAuthorization.RefreshToken refreshToken = extractRefreshToken(OAuth2Authorization);
        OidcCodeGrantAuthorization.IdToken idToken = extractIdToken(OAuth2Authorization);

        return new OidcCodeGrantAuthorization(
                OAuth2Authorization.getId(),
                OAuth2Authorization.getRegisteredClientId(),
                OAuth2Authorization.getPrincipalName(),
                OAuth2Authorization.getAuthorizedScopes(),
                accessToken,
                refreshToken,
                OAuth2Authorization.getAttribute(Principal.class.getName()),
                OAuth2Authorization.getAttribute(OAuth2AuthorizationRequest.class.getName()),
                authorizationCode,
                OAuth2Authorization.getAttribute(OAuth2ParameterNames.STATE), idToken);
    }

    static OAuth2CodeGrantAuthorization convertOAuth2AuthorizationCodeGrantAuthorization(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2CodeGrantAuthorization.AuthorizationCode authorizationCode =
                extractAuthorizationCode(OAuth2Authorization);
        OAuth2GrantAuthorization.AccessToken accessToken = extractAccessToken(OAuth2Authorization);
        OAuth2GrantAuthorization.RefreshToken refreshToken = extractRefreshToken(OAuth2Authorization);

        return new OAuth2CodeGrantAuthorization(
                OAuth2Authorization.getId(),
                OAuth2Authorization.getRegisteredClientId(),
                OAuth2Authorization.getPrincipalName(),
                OAuth2Authorization.getAuthorizedScopes(),
                accessToken,
                refreshToken,
                OAuth2Authorization.getAttribute(Principal.class.getName()),
                OAuth2Authorization.getAttribute(OAuth2AuthorizationRequest.class.getName()),
                authorizationCode,
                OAuth2Authorization.getAttribute(OAuth2ParameterNames.STATE)
        );
    }

    static OAuth2ClientCredentialsGrantAuthorization convertOAuth2ClientCredentialsGrantAuthorization(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2GrantAuthorization.AccessToken accessToken = extractAccessToken(OAuth2Authorization);

        return new OAuth2ClientCredentialsGrantAuthorization(
                OAuth2Authorization.getId(),
                OAuth2Authorization.getRegisteredClientId(),
                OAuth2Authorization.getPrincipalName(),
                OAuth2Authorization.getAuthorizedScopes(),
                accessToken
        );
    }

    static OAuth2DeviceCodeGrantAuthorization convertOAuth2DeviceCodeGrantAuthorization(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2GrantAuthorization.AccessToken accessToken = extractAccessToken(OAuth2Authorization);
        OAuth2GrantAuthorization.RefreshToken refreshToken = extractRefreshToken(OAuth2Authorization);
        OAuth2DeviceCodeGrantAuthorization.DeviceCode deviceCode = extractDeviceCode(OAuth2Authorization);
        OAuth2DeviceCodeGrantAuthorization.UserCode userCode = extractUserCode(OAuth2Authorization);

        return new OAuth2DeviceCodeGrantAuthorization(
                OAuth2Authorization.getId(),
                OAuth2Authorization.getRegisteredClientId(),
                OAuth2Authorization.getPrincipalName(),
                OAuth2Authorization.getAuthorizedScopes(),
                accessToken,
                refreshToken,
                OAuth2Authorization.getAttribute(Principal.class.getName()),
                deviceCode,
                userCode,
                OAuth2Authorization.getAttribute(OAuth2ParameterNames.SCOPE),
                OAuth2Authorization.getAttribute(OAuth2ParameterNames.STATE)
        );
    }

    static OAuth2TokenExchangeGrantAuthorization convertOAuth2TokenExchangeGrantAuthorization(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization) {

        OAuth2GrantAuthorization.AccessToken accessToken = extractAccessToken(OAuth2Authorization);

        return new OAuth2TokenExchangeGrantAuthorization(OAuth2Authorization.getId(), OAuth2Authorization.getRegisteredClientId(),
                OAuth2Authorization.getPrincipalName(), OAuth2Authorization.getAuthorizedScopes(), accessToken);
    }

    static OAuth2CodeGrantAuthorization.AuthorizationCode extractAuthorizationCode(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2CodeGrantAuthorization.AuthorizationCode authorizationCode = null;
        if (OAuth2Authorization.getToken(OAuth2AuthorizationCode.class) != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2AuthorizationCode> oauth2AuthorizationCode
                    = OAuth2Authorization.getToken(OAuth2AuthorizationCode.class);
            authorizationCode = new OAuth2CodeGrantAuthorization.AuthorizationCode(
                    oauth2AuthorizationCode.getToken().getTokenValue(),
                    oauth2AuthorizationCode.getToken().getIssuedAt(), oauth2AuthorizationCode.getToken().getExpiresAt(),
                    oauth2AuthorizationCode.isInvalidated());
        }
        return authorizationCode;
    }

    static OAuth2GrantAuthorization.AccessToken extractAccessToken(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2GrantAuthorization.AccessToken accessToken = null;
        if (OAuth2Authorization.getAccessToken() != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2AccessToken> oauth2AccessToken
                    = OAuth2Authorization.getAccessToken();
            OAuth2TokenFormat tokenFormat = null;
            if (OAuth2TokenFormat.SELF_CONTAINED.getValue()
                    .equals(oauth2AccessToken.getMetadata(OAuth2TokenFormat.class.getName()))) {
                tokenFormat = OAuth2TokenFormat.SELF_CONTAINED;
            } else if (OAuth2TokenFormat.REFERENCE.getValue()
                    .equals(oauth2AccessToken.getMetadata(OAuth2TokenFormat.class.getName()))) {
                tokenFormat = OAuth2TokenFormat.REFERENCE;
            }
            accessToken = new OAuth2GrantAuthorization.AccessToken(
                    oauth2AccessToken.getToken().getTokenValue(),
                    oauth2AccessToken.getToken().getIssuedAt(),
                    oauth2AccessToken.getToken().getExpiresAt(),
                    oauth2AccessToken.isInvalidated(),
                    oauth2AccessToken.getToken().getTokenType(),
                    oauth2AccessToken.getToken().getScopes(),
                    tokenFormat,
                    new OAuth2GrantAuthorization.ClaimsHolder(oauth2AccessToken.getClaims())
            );
        }
        return accessToken;
    }

    static OAuth2GrantAuthorization.RefreshToken extractRefreshToken(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2GrantAuthorization.RefreshToken refreshToken = null;
        if (OAuth2Authorization.getRefreshToken() != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2RefreshToken> oauth2RefreshToken
                    = OAuth2Authorization.getRefreshToken();
            refreshToken = new OAuth2GrantAuthorization.RefreshToken(
                    oauth2RefreshToken.getToken().getTokenValue(), oauth2RefreshToken.getToken().getIssuedAt(),
                    oauth2RefreshToken.getToken().getExpiresAt(), oauth2RefreshToken.isInvalidated()
            );
        }
        return refreshToken;
    }

    static OidcCodeGrantAuthorization.IdToken extractIdToken(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OidcCodeGrantAuthorization.IdToken idToken = null;
        if (OAuth2Authorization.getToken(OidcIdToken.class) != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OidcIdToken> oidcIdToken
                    = OAuth2Authorization.getToken(OidcIdToken.class);
            idToken = new OidcCodeGrantAuthorization.IdToken(
                    oidcIdToken.getToken().getTokenValue(),
                    oidcIdToken.getToken().getIssuedAt(),
                    oidcIdToken.getToken().getExpiresAt(),
                    oidcIdToken.isInvalidated(),
                    new OAuth2GrantAuthorization.ClaimsHolder(oidcIdToken.getClaims())
            );
        }
        return idToken;
    }

    static OAuth2DeviceCodeGrantAuthorization.DeviceCode extractDeviceCode(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2DeviceCodeGrantAuthorization.DeviceCode deviceCode = null;
        if (OAuth2Authorization.getToken(OAuth2DeviceCode.class) != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2DeviceCode> oauth2DeviceCode
                    = OAuth2Authorization.getToken(OAuth2DeviceCode.class);
            deviceCode = new OAuth2DeviceCodeGrantAuthorization.DeviceCode(
                    oauth2DeviceCode.getToken().getTokenValue(),
                    oauth2DeviceCode.getToken().getIssuedAt(),
                    oauth2DeviceCode.getToken().getExpiresAt(),
                    oauth2DeviceCode.isInvalidated()
            );
        }
        return deviceCode;
    }

    static OAuth2DeviceCodeGrantAuthorization.UserCode extractUserCode(
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization OAuth2Authorization
    ) {
        OAuth2DeviceCodeGrantAuthorization.UserCode userCode = null;
        if (OAuth2Authorization.getToken(OAuth2UserCode.class) != null) {
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token<OAuth2UserCode> oauth2UserCode
                    = OAuth2Authorization.getToken(OAuth2UserCode.class);
            userCode = new OAuth2DeviceCodeGrantAuthorization.UserCode(
                    oauth2UserCode.getToken().getTokenValue(),
                    oauth2UserCode.getToken().getIssuedAt(),
                    oauth2UserCode.getToken().getExpiresAt(),
                    oauth2UserCode.isInvalidated()
            );
        }
        return userCode;
    }

    static RegisteredClient convertRegisteredClient(OAuth2RegisteredClient oauth2RegisteredClient) {
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                .requireProofKey(oauth2RegisteredClient.getClientSettings().isRequireProofKey())
                .requireAuthorizationConsent(oauth2RegisteredClient.getClientSettings().isRequireAuthorizationConsent());
        if (StringUtils.hasText(oauth2RegisteredClient.getClientSettings().getJwkSetUrl())) {
            clientSettingsBuilder.jwkSetUrl(oauth2RegisteredClient.getClientSettings().getJwkSetUrl());
        }
        if (oauth2RegisteredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm() != null) {
            clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(
                    oauth2RegisteredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm()
            );
        }
        if (StringUtils.hasText(oauth2RegisteredClient.getClientSettings().getX509CertificateSubjectDN())) {
            clientSettingsBuilder
                    .x509CertificateSubjectDN(oauth2RegisteredClient.getClientSettings().getX509CertificateSubjectDN());
        }
        ClientSettings clientSettings = clientSettingsBuilder.build();

        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
        if (oauth2RegisteredClient.getTokenSettings().getAuthorizationCodeTimeToLive() != null) {
            tokenSettingsBuilder.authorizationCodeTimeToLive(
                    oauth2RegisteredClient.getTokenSettings().getAuthorizationCodeTimeToLive()
            );
        }
        if (oauth2RegisteredClient.getTokenSettings().getAccessTokenTimeToLive() != null) {
            tokenSettingsBuilder
                    .accessTokenTimeToLive(oauth2RegisteredClient.getTokenSettings().getAccessTokenTimeToLive());
        }
        if (oauth2RegisteredClient.getTokenSettings().getAccessTokenFormat() != null) {
            tokenSettingsBuilder.accessTokenFormat(oauth2RegisteredClient.getTokenSettings().getAccessTokenFormat());
        }
        if (oauth2RegisteredClient.getTokenSettings().getDeviceCodeTimeToLive() != null) {
            tokenSettingsBuilder
                    .deviceCodeTimeToLive(oauth2RegisteredClient.getTokenSettings().getDeviceCodeTimeToLive());
        }
        tokenSettingsBuilder.reuseRefreshTokens(oauth2RegisteredClient.getTokenSettings().isReuseRefreshTokens());
        if (oauth2RegisteredClient.getTokenSettings().getRefreshTokenTimeToLive() != null) {
            tokenSettingsBuilder
                    .refreshTokenTimeToLive(oauth2RegisteredClient.getTokenSettings().getRefreshTokenTimeToLive());
        }
        if (oauth2RegisteredClient.getTokenSettings().getIdTokenSignatureAlgorithm() != null) {
            tokenSettingsBuilder
                    .idTokenSignatureAlgorithm(oauth2RegisteredClient.getTokenSettings().getIdTokenSignatureAlgorithm());
        }
        tokenSettingsBuilder.x509CertificateBoundAccessTokens(
                oauth2RegisteredClient.getTokenSettings().isX509CertificateBoundAccessTokens()
        );
        TokenSettings tokenSettings = tokenSettingsBuilder.build();

        RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(oauth2RegisteredClient.getId())
                .clientId(oauth2RegisteredClient.getClientId())
                .clientIdIssuedAt(oauth2RegisteredClient.getClientIdIssuedAt())
                .clientSecret(oauth2RegisteredClient.getClientSecret())
                .clientSecretExpiresAt(oauth2RegisteredClient.getClientSecretExpiresAt())
                .clientName(oauth2RegisteredClient.getClientName())
                .clientAuthenticationMethods((clientAuthenticationMethods) ->
                        clientAuthenticationMethods.addAll(oauth2RegisteredClient.getClientAuthenticationMethods())
                )
                .authorizationGrantTypes((authorizationGrantTypes) ->
                        authorizationGrantTypes.addAll(oauth2RegisteredClient.getAuthorizationGrantTypes())
                )
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings);
        if (!CollectionUtils.isEmpty(oauth2RegisteredClient.getRedirectUris())) {
            registeredClientBuilder.redirectUris((redirectUris) ->
                    redirectUris.addAll(oauth2RegisteredClient.getRedirectUris())
            );
        }
        if (!CollectionUtils.isEmpty(oauth2RegisteredClient.getPostLogoutRedirectUris())) {
            registeredClientBuilder.postLogoutRedirectUris((postLogoutRedirectUris) ->
                    postLogoutRedirectUris.addAll(oauth2RegisteredClient.getPostLogoutRedirectUris())
            );
        }
        if (!CollectionUtils.isEmpty(oauth2RegisteredClient.getScopes())) {
            registeredClientBuilder.scopes((scopes) ->
                    scopes.addAll(oauth2RegisteredClient.getScopes())
            );
        }

        return registeredClientBuilder.build();
    }

    static org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent convertOAuth2AuthorizationConsent(
            OAuth2AuthorizationConsent oAuth2AuthorizationConsent
    ) {
        return org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent.withId(
                        oAuth2AuthorizationConsent.getRegisteredClientId(),
                        oAuth2AuthorizationConsent.getPrincipalName()
                )
                .authorities((authorities) ->
                        authorities.addAll(oAuth2AuthorizationConsent.getAuthorities())
                )
                .build();
    }

    static void mapOAuth2AuthorizationGrantAuthorization(
            OAuth2GrantAuthorization authorizationGrantOAuth2GrantAuthorization,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {

        if (authorizationGrantOAuth2GrantAuthorization instanceof OidcCodeGrantAuthorization authorizationGrant) {
            mapOidcAuthorizationCodeGrantAuthorization(authorizationGrant, builder);
        } else if (authorizationGrantOAuth2GrantAuthorization instanceof OAuth2CodeGrantAuthorization authorizationGrant) {
            mapOAuth2AuthorizationCodeGrantAuthorization(authorizationGrant, builder);
        } else if (authorizationGrantOAuth2GrantAuthorization instanceof OAuth2ClientCredentialsGrantAuthorization authorizationGrant) {
            mapOAuth2ClientCredentialsGrantAuthorization(authorizationGrant, builder);
        } else if (authorizationGrantOAuth2GrantAuthorization instanceof OAuth2DeviceCodeGrantAuthorization authorizationGrant) {
            mapOAuth2DeviceCodeGrantAuthorization(authorizationGrant, builder);
        } else if (authorizationGrantOAuth2GrantAuthorization instanceof OAuth2TokenExchangeGrantAuthorization authorizationGrant) {
            mapOAuth2TokenExchangeGrantAuthorization(authorizationGrant, builder);
        }
    }

    static void mapOidcAuthorizationCodeGrantAuthorization(
            OidcCodeGrantAuthorization authorizationCodeGrantAuthorization,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {

        mapOAuth2AuthorizationCodeGrantAuthorization(authorizationCodeGrantAuthorization, builder);
        mapIdToken(authorizationCodeGrantAuthorization.getIdToken(), builder);
    }

    static void mapOAuth2AuthorizationCodeGrantAuthorization(
            OAuth2CodeGrantAuthorization authorizationCodeGrantAuthorization,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {

        builder.id(authorizationCodeGrantAuthorization.getId())
                .principalName(authorizationCodeGrantAuthorization.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(authorizationCodeGrantAuthorization.getAuthorizedScopes())
                .attribute(Principal.class.getName(), authorizationCodeGrantAuthorization.getPrincipal())
                .attribute(OAuth2AuthorizationRequest.class.getName(),
                        authorizationCodeGrantAuthorization.getAuthorizationRequest());
        if (StringUtils.hasText(authorizationCodeGrantAuthorization.getState())) {
            builder.attribute(OAuth2ParameterNames.STATE, authorizationCodeGrantAuthorization.getState());
        }

        mapAuthorizationCode(authorizationCodeGrantAuthorization.getAuthorizationCode(), builder);
        mapAccessToken(authorizationCodeGrantAuthorization.getAccessToken(), builder);
        mapRefreshToken(authorizationCodeGrantAuthorization.getRefreshToken(), builder);
    }

    static void mapOAuth2ClientCredentialsGrantAuthorization(
            OAuth2ClientCredentialsGrantAuthorization clientCredentialsGrantAuthorization,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {

        builder.id(clientCredentialsGrantAuthorization.getId())
                .principalName(clientCredentialsGrantAuthorization.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(clientCredentialsGrantAuthorization.getAuthorizedScopes());

        mapAccessToken(clientCredentialsGrantAuthorization.getAccessToken(), builder);
    }

    static void mapOAuth2DeviceCodeGrantAuthorization(
            OAuth2DeviceCodeGrantAuthorization deviceCodeGrantAuthorization,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {

        builder.id(deviceCodeGrantAuthorization.getId())
                .principalName(deviceCodeGrantAuthorization.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizedScopes(deviceCodeGrantAuthorization.getAuthorizedScopes());
        if (deviceCodeGrantAuthorization.getPrincipal() != null) {
            builder.attribute(Principal.class.getName(), deviceCodeGrantAuthorization.getPrincipal());
        }
        if (deviceCodeGrantAuthorization.getRequestedScopes() != null) {
            builder.attribute(OAuth2ParameterNames.SCOPE, deviceCodeGrantAuthorization.getRequestedScopes());
        }
        if (StringUtils.hasText(deviceCodeGrantAuthorization.getDeviceState())) {
            builder.attribute(OAuth2ParameterNames.STATE, deviceCodeGrantAuthorization.getDeviceState());
        }

        mapAccessToken(deviceCodeGrantAuthorization.getAccessToken(), builder);
        mapRefreshToken(deviceCodeGrantAuthorization.getRefreshToken(), builder);
        mapDeviceCode(deviceCodeGrantAuthorization.getDeviceCode(), builder);
        mapUserCode(deviceCodeGrantAuthorization.getUserCode(), builder);
    }

    static void mapOAuth2TokenExchangeGrantAuthorization(
            OAuth2TokenExchangeGrantAuthorization tokenExchangeGrantAuthorization,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {

        builder.id(tokenExchangeGrantAuthorization.getId())
                .principalName(tokenExchangeGrantAuthorization.getPrincipalName())
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizedScopes(tokenExchangeGrantAuthorization.getAuthorizedScopes());

        mapAccessToken(tokenExchangeGrantAuthorization.getAccessToken(), builder);
    }

    static void mapAuthorizationCode(
            OAuth2CodeGrantAuthorization.AuthorizationCode authorizationCode,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {
        if (authorizationCode == null) {
            return;
        }
        OAuth2AuthorizationCode oauth2AuthorizationCode = new OAuth2AuthorizationCode(
                authorizationCode.getTokenValue(),
                authorizationCode.getIssuedAt(),
                authorizationCode.getExpiresAt()
        );
        builder.token(oauth2AuthorizationCode, (metadata) -> metadata
                .put(
                        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                        authorizationCode.isInvalidated()
                )
        );
    }

    static void mapAccessToken(
            OAuth2GrantAuthorization.AccessToken accessToken,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {
        if (accessToken == null) {
            return;
        }
        OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(
                accessToken.getTokenType(),
                accessToken.getTokenValue(),
                accessToken.getIssuedAt(),
                accessToken.getExpiresAt(),
                accessToken.getScopes()
        );
        builder.token(oauth2AccessToken, (metadata) -> {
            metadata.put(
                    org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                    accessToken.isInvalidated()
            );
            metadata.put(
                    org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                    accessToken.getClaims().claims()
            );
            metadata.put(OAuth2TokenFormat.class.getName(), accessToken.getTokenFormat().getValue());
        });
    }

    static void mapRefreshToken(
            OAuth2GrantAuthorization.RefreshToken refreshToken,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {
        if (refreshToken == null) {
            return;
        }
        OAuth2RefreshToken oauth2RefreshToken = new OAuth2RefreshToken(refreshToken.getTokenValue(),
                refreshToken.getIssuedAt(), refreshToken.getExpiresAt());
        builder.token(oauth2RefreshToken, (metadata) -> metadata
                .put(
                        org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                        refreshToken.isInvalidated()
                )
        );
    }

    static void mapIdToken(
            OidcCodeGrantAuthorization.IdToken idToken,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {
        if (idToken == null) {
            return;
        }
        OidcIdToken oidcIdToken = new OidcIdToken(idToken.getTokenValue(), idToken.getIssuedAt(),
                idToken.getExpiresAt(), idToken.getClaims().claims());
        builder.token(oidcIdToken, (metadata) -> {
            metadata.put(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, idToken.isInvalidated());
            metadata.put(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims().claims());
        });
    }

    static void mapDeviceCode(
            OAuth2DeviceCodeGrantAuthorization.DeviceCode deviceCode,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {
        if (deviceCode == null) {
            return;
        }
        OAuth2DeviceCode oauth2DeviceCode = new OAuth2DeviceCode(deviceCode.getTokenValue(), deviceCode.getIssuedAt(),
                deviceCode.getExpiresAt());
        builder.token(oauth2DeviceCode, (metadata) -> metadata.put(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                deviceCode.isInvalidated()));
    }

    static void mapUserCode(
            OAuth2DeviceCodeGrantAuthorization.UserCode userCode,
            org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Builder builder
    ) {
        if (userCode == null) {
            return;
        }
        OAuth2UserCode oauth2UserCode = new OAuth2UserCode(userCode.getTokenValue(), userCode.getIssuedAt(),
                userCode.getExpiresAt());
        builder.token(oauth2UserCode, (metadata) -> metadata.put(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
                userCode.isInvalidated()));
    }
}
