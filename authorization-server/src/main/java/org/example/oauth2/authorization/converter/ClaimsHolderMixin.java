package org.example.oauth2.authorization.converter;

import com.fasterxml.jackson.annotation.*;

import java.util.Map;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(
        fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
abstract class ClaimsHolderMixin {

    @JsonCreator
    ClaimsHolderMixin(@JsonProperty("claims") Map<String, Object> claims) {
    }
}
