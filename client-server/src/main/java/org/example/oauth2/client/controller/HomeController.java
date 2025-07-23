package org.example.oauth2.client.controller;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@RestController
public class HomeController {

    private final WebClient webClient;

    public HomeController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping
    public List<String> getProducts(
            @RegisteredOAuth2AuthorizedClient
            OAuth2AuthorizedClient authorizedClient
    ) {
        ParameterizedTypeReference<List<String>> typeRef = new ParameterizedTypeReference<>() {};
        return this.webClient.get()
                .uri("http://127.0.0.1:8090/products")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(typeRef)
                .block();
    }
}
