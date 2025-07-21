package org.example.oauth2.authorization.repository;

import org.example.oauth2.authorization.model.OAuth2AuthorizationConsent;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuth2AuthorizationConsentRepository extends CrudRepository<OAuth2AuthorizationConsent, String> {

	OAuth2AuthorizationConsent findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

	void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}