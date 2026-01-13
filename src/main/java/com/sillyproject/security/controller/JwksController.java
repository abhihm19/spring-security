package com.sillyproject.security.controller;

import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sillyproject.security.security.JwtKeyStoreProvider;

@RestController
public class JwksController {

    private final JwtKeyStoreProvider jwtKeyStoreProvider;

    public JwksController(JwtKeyStoreProvider jwtKeyStoreProvider) {
        this.jwtKeyStoreProvider = jwtKeyStoreProvider;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        return jwtKeyStoreProvider.toJwks();
    }
}

