package com.sillyproject.security.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.UUID;
import java.util.Date;
import java.util.Base64;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
	
	private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);
	
	@Value("${app.jwt.secret}")
	private String jwtSecret;

	@Value("${access.token.validity}")
	private long accessTokenValidity;

	@Value("${refresh.token.validity}")
	private long refreshTokenValidity;

	public String generateAccessToken(String username) {
		return Jwts.builder()
				.subject(username)
				.claim("type", "access")
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + accessTokenValidity))
				.signWith(key())
				.compact();
	}

	public String generateRefreshToken(String username) {
		return Jwts.builder()
				.subject(username)
				.claim("type", "refresh")
				.id(UUID.randomUUID().toString())
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + refreshTokenValidity))
				.signWith(key())
				.compact();
	}
	
	private Key key() {
		return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
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
		return Jwts.parser()
				.verifyWith((SecretKey) key())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

}
