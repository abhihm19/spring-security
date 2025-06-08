package com.sillyproject.security.security;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
	
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
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + refreshTokenValidity))
				.signWith(key())
				.compact();
	}
	
	private Key key() {
		return Keys.hmacShaKeyFor(jwtSecret.getBytes());
	}

	public String getUsername(String token) {
		SecretKey key = (SecretKey) key();
		return Jwts.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getSubject();
	
	}

	public boolean validateToken(String token, String expectedType) {
		try {
			Claims claims = Jwts.parser()
					.verifyWith((SecretKey) key())
					.build()
					.parseSignedClaims(token)
					.getPayload();

			String tokenType = claims.get("type", String.class);
			return tokenType != null && tokenType.equals(expectedType) && !isTokenExpired(claims);
		} catch (Exception ex) {
			return false;
		}
	}

	private boolean isTokenExpired(Claims claims) {
			return claims.getExpiration().before(new Date());
	}

	public Date getExpirationDate(String token) {

		Claims claims = Jwts.parser()
				.verifyWith((SecretKey) key())
				.build()
				.parseSignedClaims(token)
				.getPayload();

		return claims.getExpiration();
	}

}
