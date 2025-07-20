package org.example.oauth2.client.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class HomeController {

    private final WebClient webClient;

    public HomeController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping("/")
    public String home(Model model, OAuth2AuthenticationToken authentication) {
        if (authentication != null) {
            model.addAttribute("userName", authentication.getName());
            model.addAttribute("authorities", authentication.getAuthorities());
        }
        return "index";
    }

    @GetMapping("/profile")
    public String profile(Model model, OAuth2AuthorizedClient authorizedClient) {
        String userProfile = this.webClient
                .get()
                .uri("http://localhost:8081/api/user/profile")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        model.addAttribute("userProfile", userProfile);
        return "profile";
    }

    @GetMapping("/admin")
    public String admin(Model model, OAuth2AuthorizedClient authorizedClient) {
        try {
            String users = this.webClient
                    .get()
                    .uri("http://localhost:8081/api/admin/users")
                    .attributes(oauth2AuthorizedClient(authorizedClient))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            model.addAttribute("users", users);
        } catch (Exception e) {
            model.addAttribute("error", "Access denied or insufficient permissions");
        }
        return "admin";
    }
}
