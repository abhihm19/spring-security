package com.sillyproject.security.security;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

/**
 * Loads RSA keys from a keystore and exposes:
 * - active signing key (private key) + kid (alias)
 * - verification keys (public keys) keyed by kid (alias)
 * - JWKS representation for public keys
 *
 * Recommended in production: store the keystore and passwords in AWS Secrets Manager / Parameter Store.
 */
@Component
public class JwtKeyStoreProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtKeyStoreProvider.class);

    private final String activeKid;
    private final PrivateKey activePrivateKey;
    private final Map<String, PublicKey> publicKeysByKid;

    public JwtKeyStoreProvider(
            ResourceLoader resourceLoader,
            @Value("${app.jwt.keystore.path:}") String keystorePath,
            @Value("${app.jwt.keystore.password:}") String keystorePassword,
            @Value("${app.jwt.keystore.key-password:}") String keyPassword,
            @Value("${app.jwt.keystore.active-alias:}") String activeAlias) {

        // Dev fallback: if keystore isn't configured, generate an ephemeral RSA keypair.
        // Production should always provide a stable keystore (otherwise tokens break on restart).
        if (keystorePath == null || keystorePath.isBlank()) {
            try {
                log.warn("JWT keystore not configured; generating ephemeral RSA keypair for dev.");
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.generateKeyPair();
                this.activeKid = "dev-key";
                this.activePrivateKey = (PrivateKey) kp.getPrivate();
                this.publicKeysByKid = Map.of(this.activeKid, kp.getPublic());
                return;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to generate dev RSA keypair", e);
            }
        }
        if (keystorePassword == null || keystorePassword.isBlank()) {
            throw new IllegalStateException("Missing required property: app.jwt.keystore.password");
        }
        if (activeAlias == null || activeAlias.isBlank()) {
            throw new IllegalStateException("Missing required property: app.jwt.keystore.active-alias");
        }

        char[] storePass = keystorePassword.toCharArray();
        char[] keyPass = (keyPassword == null || keyPassword.isBlank()) ? storePass : keyPassword.toCharArray();

        try {
            Resource resource = resourceLoader.getResource(keystorePath);
            if (!resource.exists()) {
                throw new IllegalStateException("Keystore not found: " + keystorePath);
            }

            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream is = resource.getInputStream()) {
                ks.load(is, storePass);
            }

            // Load all public keys from certificates
            Map<String, PublicKey> publics = new LinkedHashMap<>();
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = ks.getCertificate(alias);
                if (cert != null) {
                    publics.put(alias, cert.getPublicKey());
                }
            }

            if (publics.isEmpty()) {
                throw new IllegalStateException("No certificates/public keys found in keystore");
            }

            // Load active private key
            Key key = ks.getKey(activeAlias, keyPass);
            if (!(key instanceof PrivateKey privateKey)) {
                throw new IllegalStateException("Active alias does not contain a PrivateKey: " + activeAlias);
            }

            // Ensure there is a corresponding public key for the active alias
            if (!publics.containsKey(activeAlias)) {
                throw new IllegalStateException("No public key/certificate found for active alias: " + activeAlias);
            }

            this.activeKid = activeAlias;
            this.activePrivateKey = privateKey;
            this.publicKeysByKid = Map.copyOf(publics);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load JWT keystore keys", e);
        }
    }

    public String getActiveKid() {
        return activeKid;
    }

    public PrivateKey getActivePrivateKey() {
        return activePrivateKey;
    }

    public PublicKey getPublicKey(String kid) {
        if (kid == null || kid.isBlank()) {
            return null;
        }
        return publicKeysByKid.get(kid);
    }

    public Map<String, PublicKey> getAllPublicKeys() {
        return publicKeysByKid;
    }

    public Map<String, Object> toJwks() {
        List<Map<String, Object>> keys = publicKeysByKid.entrySet().stream()
                .map(e -> toRsaJwk(e.getKey(), e.getValue()))
                .toList();
        return Map.of("keys", keys);
    }

    private Map<String, Object> toRsaJwk(String kid, PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey rsa)) {
            throw new IllegalStateException("JWKS only supports RSA public keys. kid=" + kid);
        }

        // Base64url-encode modulus (n) and exponent (e) per JWK spec
        String n = base64UrlUnsigned(rsa.getModulus().toByteArray());
        String e = base64UrlUnsigned(rsa.getPublicExponent().toByteArray());

        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("kid", kid);
        jwk.put("n", n);
        jwk.put("e", e);
        return jwk;
    }

    private String base64UrlUnsigned(byte[] bytes) {
        // Remove leading zero sign byte if present
        int start = 0;
        while (start < bytes.length - 1 && bytes[start] == 0) {
            start++;
        }
        byte[] unsigned = (start == 0) ? bytes : java.util.Arrays.copyOfRange(bytes, start, bytes.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
    }
}

