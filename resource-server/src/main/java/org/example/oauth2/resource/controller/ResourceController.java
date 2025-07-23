package org.example.oauth2.resource.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
public class ResourceController {

    @GetMapping("/products")
    public ResponseEntity<List<String>> getAllProducts() {
        return ResponseEntity.ok(List.of("Product1", "Product2", "Product3", "Product4", "Product5"));
    }
}
