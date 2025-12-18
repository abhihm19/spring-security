package com.sillyproject.security.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Hashes refresh tokens before persistence.
 *
 * We use HMAC-SHA256 with a server-side "pepper" so a DB leak cannot be used to
 * precompute hashes or validate guesses without also having the pepper.
 */
@Component
public class TokenHashingService {

    private final byte[] pepperKeyBytes;

    public TokenHashingService(@Value("${app.refresh.token.pepper}") String pepper) {
        if (pepper == null || pepper.trim().isEmpty()) {
            throw new IllegalStateException("Property 'app.refresh.token.pepper' must be set");
        }
        this.pepperKeyBytes = pepper.getBytes(StandardCharsets.UTF_8);
    }

    public String hash(String rawRefreshToken) {
        if (rawRefreshToken == null) {
            throw new IllegalArgumentException("rawRefreshToken cannot be null");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepperKeyBytes, "HmacSHA256"));
            byte[] digest = mac.doFinal(rawRefreshToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash refresh token", e);
        }
    }
}

