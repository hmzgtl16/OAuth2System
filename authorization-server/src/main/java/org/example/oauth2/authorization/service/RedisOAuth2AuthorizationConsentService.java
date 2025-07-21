package org.example.oauth2.authorization.service;

import org.example.oauth2.authorization.model.OAuth2AuthorizationConsent;
import org.example.oauth2.authorization.repository.OAuth2AuthorizationConsentRepository;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.util.Assert;

public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	private final OAuth2AuthorizationConsentRepository oAuth2AuthorizationConsentRepository;

	public RedisOAuth2AuthorizationConsentService(
			OAuth2AuthorizationConsentRepository oAuth2AuthorizationConsentRepository
	) {
		Assert.notNull(oAuth2AuthorizationConsentRepository, "oAuth2AuthorizationConsentRepository cannot be null");
		this.oAuth2AuthorizationConsentRepository = oAuth2AuthorizationConsentRepository;
	}

	@Override
	public void save(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		OAuth2AuthorizationConsent oAuth2AuthorizationConsent = ModelMapper.convertOAuth2UserConsent(authorizationConsent);
		this.oAuth2AuthorizationConsentRepository.save(oAuth2AuthorizationConsent);
	}

	@Override
	public void remove(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		this.oAuth2AuthorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
				authorizationConsent.getRegisteredClientId(),
				authorizationConsent.getPrincipalName()
		);
	}

	@Nullable
	@Override
	public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent findById(
			String registeredClientId,
			String principalName
	) {
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		OAuth2AuthorizationConsent oAuth2AuthorizationConsent = this.oAuth2AuthorizationConsentRepository
				.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName);
		return oAuth2AuthorizationConsent != null ? ModelMapper.convertOAuth2AuthorizationConsent(oAuth2AuthorizationConsent) : null;
	}

}