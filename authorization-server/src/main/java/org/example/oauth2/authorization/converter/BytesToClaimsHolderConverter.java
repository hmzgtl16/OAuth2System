package org.example.oauth2.authorization.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.oauth2.authorization.model.OAuth2GrantAuthorization;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

@ReadingConverter
public class BytesToClaimsHolderConverter implements Converter<byte[], OAuth2GrantAuthorization.ClaimsHolder> {

    private final Jackson2JsonRedisSerializer<OAuth2GrantAuthorization.ClaimsHolder> serializer;

    public BytesToClaimsHolderConverter() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModules(SecurityJackson2Modules.getModules(BytesToClaimsHolderConverter.class.getClassLoader()));
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        objectMapper.addMixIn(OAuth2GrantAuthorization.ClaimsHolder.class, ClaimsHolderMixin.class);
        this.serializer = new Jackson2JsonRedisSerializer<>(objectMapper, OAuth2GrantAuthorization.ClaimsHolder.class);
    }

    @Override
    public OAuth2GrantAuthorization.ClaimsHolder convert(byte[] value) {
        return this.serializer.deserialize(value);
    }
}
