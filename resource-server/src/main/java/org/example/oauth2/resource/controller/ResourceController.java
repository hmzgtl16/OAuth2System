package org.example.oauth2.resource.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public/info")
    public ResponseEntity<Map<String, String>> getPublicInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("message", "This is public information");
        info.put("timestamp", new Date().toString());
        return ResponseEntity.ok(info);
    }

    @GetMapping("/user/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile(
            JwtAuthenticationToken token
    ) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("username", token.getName());
        profile.put("authorities", token.getAuthorities());
        profile.put("scopes", token.getToken().getClaimAsStringList("scope"));
        return ResponseEntity.ok(profile);
    }

    @GetMapping("/admin/users")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<List<Map<String, String>>> getAllUsers() {
        List<Map<String, String>> users = Arrays.asList(
            Map.of("id", "1", "username", "admin", "role", "ADMIN"),
            Map.of("id", "2", "username", "user", "role", "USER")
        );
        return ResponseEntity.ok(users);
    }

    @PostMapping("/admin/users")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    public ResponseEntity<Map<String, String>> createUser(
            @RequestBody Map<String, String> user
    ) {
        user.put("id", String.valueOf(new Random().nextInt(1000)));
        user.put("created", new Date().toString());
        return ResponseEntity.ok(user);
    }
}
