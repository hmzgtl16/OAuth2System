package org.example.oauth2.authorization.config;

import org.example.oauth2.authorization.converter.*;
import org.example.oauth2.authorization.repository.OAuth2AuthorizationGrantAuthorizationRepository;
import org.example.oauth2.authorization.repository.OAuth2RegisteredClientRepository;
import org.example.oauth2.authorization.repository.OAuth2UserConsentRepository;
import org.example.oauth2.authorization.service.RedisOAuth2AuthorizationConsentService;
import org.example.oauth2.authorization.service.RedisOAuth2AuthorizationService;
import org.example.oauth2.authorization.service.RedisRegisteredClientRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.convert.RedisCustomConversions;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Arrays;

@Configuration
@EnableRedisRepositories("org.example.oauth2.authorization.repository")
public class RedisConfig {

    @Value("${spring.data.redis.host}")
    private String host;

    @Value("${spring.data.redis.port}")
    private int port;

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory(new RedisStandaloneConfiguration(host, port));
    }

    @Bean
    public RedisTemplate<?, ?> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        return redisTemplate;
    }

    @Bean
    public RedisCustomConversions redisCustomConversions() {
        return new RedisCustomConversions(
                Arrays.asList(
                        new UsernamePasswordAuthenticationTokenToBytesConverter(),
                        new BytesToUsernamePasswordAuthenticationTokenConverter(),
                        new OAuth2AuthorizationRequestToBytesConverter(),
                        new BytesToOAuth2AuthorizationRequestConverter(),
                        new ClaimsHolderToBytesConverter(),
                        new BytesToClaimsHolderConverter()
                )
        );
    }

    @Bean
    public RedisRegisteredClientRepository registeredClientRepository(
            OAuth2RegisteredClientRepository registeredClientRepository
    ) {
        RedisRegisteredClientRepository redisRegisteredClientRepository =
                new RedisRegisteredClientRepository(registeredClientRepository);
        redisRegisteredClientRepository.save(RegisteredClients.oidcClient());

        return redisRegisteredClientRepository;
    }

    @Bean
    public RedisOAuth2AuthorizationService authorizationService(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationGrantAuthorizationRepository authorizationGrantAuthorizationRepository
    ) {
        return new RedisOAuth2AuthorizationService(
                registeredClientRepository,
                authorizationGrantAuthorizationRepository
        );
    }

    @Bean
    public RedisOAuth2AuthorizationConsentService authorizationConsentService(
            OAuth2UserConsentRepository userConsentRepository
    ) {
        return new RedisOAuth2AuthorizationConsentService(userConsentRepository);
    }
}

