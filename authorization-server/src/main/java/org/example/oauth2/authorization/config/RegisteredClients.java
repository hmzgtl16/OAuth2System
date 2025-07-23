package org.example.oauth2.authorization.config;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.UUID;

public class RegisteredClients {

    public static RegisteredClient oidcClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("products-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/products-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .postLogoutRedirectUri("http://127.0.0.1:9000/login")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("write")
                .clientSettings(
                        ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .build()
                )
                .build();
    }
}

