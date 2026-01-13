package com.sillyproject.security.security;

import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;

@Component
public class JwtTokenProvider {
	
	private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

	private final JwtKeyStoreProvider keyStoreProvider;
	private final ObjectMapper objectMapper;
	private final long accessTokenValidity;
	private final long refreshTokenValidity;
	private final String jwtIssuer;
	private final String jwtAudience;

	public JwtTokenProvider(
			JwtKeyStoreProvider keyStoreProvider,
			ObjectMapper objectMapper,
			org.springframework.core.env.Environment env) {
		this.keyStoreProvider = keyStoreProvider;
		this.objectMapper = objectMapper;
		this.accessTokenValidity = Long.parseLong(env.getProperty("access.token.validity", "1800000"));
		this.refreshTokenValidity = Long.parseLong(env.getProperty("refresh.token.validity", "604800000"));
		this.jwtIssuer = env.getProperty("app.jwt.issuer", "");
		this.jwtAudience = env.getProperty("app.jwt.audience", "");
	}

	public String generateAccessToken(String username) {
		return generateAccessToken(username, 0);
	}

	public String generateAccessToken(String username, int tokenVersion) {
		var builder = Jwts.builder()
				.header().keyId(keyStoreProvider.getActiveKid()).and()
				.subject(username)
				.claim("type", "access")
				.claim("ver", tokenVersion)
				.id(UUID.randomUUID().toString())
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + accessTokenValidity));

		if (jwtIssuer != null && !jwtIssuer.isBlank()) {
			builder.issuer(jwtIssuer);
		}
		if (jwtAudience != null && !jwtAudience.isBlank()) {
			builder.audience().add(jwtAudience).and();
		}

		return builder.signWith(keyStoreProvider.getActivePrivateKey(), Jwts.SIG.RS256).compact();
	}

	public String generateRefreshToken(String username) {
		return generateRefreshToken(username, new Date(System.currentTimeMillis() + refreshTokenValidity));
	}

	/**
	 * Generate a refresh token with an explicit expiration time. This enables "absolute session lifetime"
	 * rotation (rotated refresh tokens do not extend the session beyond its original expiry).
	 */
	public String generateRefreshToken(String username, Date expiresAt) {
		var builder = Jwts.builder()
				.header().keyId(keyStoreProvider.getActiveKid()).and()
				.subject(username)
				.claim("type", "refresh")
				.id(UUID.randomUUID().toString())
				.issuedAt(new Date())
				.expiration(expiresAt);

		if (jwtIssuer != null && !jwtIssuer.isBlank()) {
			builder.issuer(jwtIssuer);
		}
		if (jwtAudience != null && !jwtAudience.isBlank()) {
			builder.audience().add(jwtAudience).and();
		}

		return builder.signWith(keyStoreProvider.getActivePrivateKey(), Jwts.SIG.RS256).compact();
	}

	public String getUsername(String token) {
		try {
			return parseClaims(token).getSubject();
		} catch (io.jsonwebtoken.security.SignatureException ex) {
			log.error("Token signature verification failed - token may be tampered");
			throw ex;
		} catch (io.jsonwebtoken.ExpiredJwtException ex) {
			log.error("Token has expired");
			throw ex;
		} catch (io.jsonwebtoken.MalformedJwtException ex) {
			log.error("Token is malformed - invalid format");
			throw ex;
		} catch (io.jsonwebtoken.UnsupportedJwtException ex) {
			log.error("Token format is not supported");
			throw ex;
		} catch (io.jsonwebtoken.security.SecurityException ex) {
			log.error("Token security validation failed");
			throw ex;
		} catch (Exception ex) {
			log.error("Unexpected error parsing token: {}", ex.getMessage());
			throw new io.jsonwebtoken.security.SecurityException("Invalid token", ex);
		}
	}

	public String getJti(String token) {
		try {
			return parseClaims(token).getId();
		} catch (Exception ex) {
			throw ex;
		}
	}

	public Date getExpirationDate(String token) {
		return parseClaims(token).getExpiration();
	}

	public Integer getTokenVersion(String token) {
		try {
			return parseClaims(token).get("ver", Integer.class);
		} catch (Exception ex) {
			return null;
		}
	}

	public boolean validateToken(String token, String expectedType) {
		// Basic format check: JWT tokens have 3 parts separated by dots
		if (token == null || token.trim().isEmpty()) {
			log.warn("Token is null or empty");
			return false;
		}
		
		token = token.trim();
		
		// Strict structural check: exactly 3 non-empty parts
		String[] parts = token.split("\\.", -1);
		if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
			log.warn("Token format invalid - expected 3 non-empty parts separated by dots");
			return false;
		}

		// Verify each part contains only valid base64url characters (A-Z, a-z, 0-9, -, _)
		// and ensure no extra characters exist outside the parts
		String validTokenPattern = "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$";
		if (!token.matches(validTokenPattern)) {
			log.warn("Token contains invalid characters - only base64url characters (A-Z, a-z, 0-9, -, _) allowed");
			return false;
		}
		
		// IMPORTANT: enforce canonical base64url encoding for each part.
		// This prevents accepting tokens where extra characters are appended but ignored by lenient decoders.
		if (!isCanonicalBase64Url(parts[0]) || !isCanonicalBase64Url(parts[1]) || !isCanonicalBase64Url(parts[2])) {
			log.warn("Token rejected - non-canonical base64url encoding detected (possible tampering)");
			return false;
		}
		
		try {
			// Parse and verify signature - this will throw exception if signature doesn't match
			Claims claims = parseClaims(token);

			String tokenType = claims.get("type", String.class);
			boolean isValid = tokenType != null && tokenType.equals(expectedType) && !isTokenExpired(claims);

			// Optional issuer/audience enforcement (recommended in production)
			if (isValid && jwtIssuer != null && !jwtIssuer.isBlank()) {
				isValid = jwtIssuer.equals(claims.getIssuer());
			}
			if (isValid && jwtAudience != null && !jwtAudience.isBlank()) {
				isValid = claims.getAudience() != null && claims.getAudience().contains(jwtAudience);
			}
			
			if (!isValid) {
				log.warn("Token validation failed - type mismatch or expired. Expected type: {}, Actual type: {}", 
					expectedType, tokenType);
			}
			
			return isValid;
		} catch (io.jsonwebtoken.security.SignatureException ex) {
			log.warn("Token signature verification failed - token may be tampered: {}", ex.getMessage());
			return false;
		} catch (io.jsonwebtoken.MalformedJwtException ex) {
			log.warn("Token is malformed - invalid JWT format: {}", ex.getMessage());
			return false;
		} catch (io.jsonwebtoken.ExpiredJwtException ex) {
			log.warn("Token has expired");
			return false;
		} catch (Exception ex) {
			log.warn("Token validation failed with unexpected error: {}", ex.getMessage());
			return false;
		}
	}
	
	private boolean isCanonicalBase64Url(String part) {
		try {
			byte[] decoded = base64UrlDecode(part);
			String reEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(decoded);
			return part.equals(reEncoded);
		} catch (Exception ex) {
			return false;
		}
	}
	
	private byte[] base64UrlDecode(String value) {
		// Java's Base64 decoder expects padding in some cases; JWT uses base64url without padding.
		int mod = value.length() % 4;
		String padded = switch (mod) {
			case 0 -> value;
			case 2 -> value + "==";
			case 3 -> value + "=";
			default -> throw new IllegalArgumentException("Invalid base64url length");
		};
		return Base64.getUrlDecoder().decode(padded);
	}

	private boolean isTokenExpired(Claims claims) {
			return claims.getExpiration().before(new Date());
	}

	private Claims parseClaims(String token) {
		String kid = extractKid(token);
		java.security.PublicKey verificationKey = keyStoreProvider.getPublicKey(kid);
		if (verificationKey == null) {
			throw new io.jsonwebtoken.security.SecurityException("Unknown kid");
		}
		return Jwts.parser()
				.verifyWith(verificationKey)
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

	private String extractKid(String token) {
		try {
			String[] parts = token.split("\\.", -1);
			if (parts.length != 3) {
				throw new IllegalArgumentException("Invalid JWT structure");
			}
			byte[] headerBytes = base64UrlDecode(parts[0]);
			@SuppressWarnings("unchecked")
			Map<String, Object> header = objectMapper.readValue(headerBytes, Map.class);
			Object kid = header.get("kid");
			return kid == null ? null : kid.toString();
		} catch (Exception e) {
			throw new io.jsonwebtoken.security.SecurityException("Unable to parse token header", e);
		}
	}

}
