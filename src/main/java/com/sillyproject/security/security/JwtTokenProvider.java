package com.sillyproject.security.security;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import io.jsonwebtoken.JwtException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
	
//	@Value("${app.jwt-secret}")
	private static String jwtSecret = "e6x4d(_n91u7bvrg*k73ja(h)ty^5flbjaer3=!&!y=z3m*n^g";
//	@Value("${app-jwt-expiration-milliseconds}")
	private static long jwtExpirationDate = 879863;
	
	public static String generateToken(String username) {
//		String username = authentication.getName();		
		Date currentDate = new Date();		
		Date expirationDate = new Date(currentDate.getTime() + jwtExpirationDate);
		
		String token =Jwts.builder()
			.subject(username)
			.issuedAt(new Date())
			.expiration(expirationDate)
			.signWith(key())
			.compact();
		
		return token;
		
	}
	
	private static Key key() {
		return Keys.hmacShaKeyFor(jwtSecret.getBytes());
	}
	
	//get username from jwt token
	public static String getUsername(String token) {
		SecretKey key = (SecretKey) key();
		return Jwts.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getSubject();
	
	}
	
	//validate jwt token
	public static boolean validateToken(String token) {
		try {
			Jwts.parser()
					.verifyWith((SecretKey) key())
					.build()
					.parseSignedClaims(token);
			return !isTokenExpired(token);
		} catch (Exception e) {
			return false;
		}
	}

	private static boolean isTokenExpired(String token) {
		Date expiration = Jwts.parser()
				.verifyWith((SecretKey) key())
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getExpiration();

		return expiration.before(new Date());
	}
	
	public static void main(String[] args) {
		String token = generateToken("Abhi");
		System.out.println(token);
		System.out.println(getUsername(token));
		System.out.println(validateToken(token));

		PasswordEncoder passwordEncoder =  new BCryptPasswordEncoder();
		System.out.println(passwordEncoder.encode("1234"));
	}
}
