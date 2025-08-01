package org.example.oauth2.authorization.model;

import java.util.Set;

public class OAuth2ClientCredentialsGrantAuthorization extends OAuth2GrantAuthorization {

	public OAuth2ClientCredentialsGrantAuthorization(String id, String registeredClientId, String principalName, Set<String> authorizedScopes,
      AccessToken accessToken) {
        super(id, registeredClientId, principalName, authorizedScopes, accessToken, null);
    }
}