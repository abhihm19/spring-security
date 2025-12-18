package com.sillyproject.security.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
	
	private JwtTokenProvider jwtTokenProvider;
	private UserDetailsService userDetailsService;
	
	
	public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, UserDetailsService userDetailsService) {
		this.jwtTokenProvider = jwtTokenProvider;
		this.userDetailsService = userDetailsService;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String requestPath = request.getRequestURI();
		String method = request.getMethod();
		log.debug("JWT Filter - Processing request: {} {}", method, requestPath);
		
		//get jwt token from http request
		String token = getTokenFromRequest(request);
		
		if (!StringUtils.hasText(token)) {
			log.debug("JWT Filter - No token found in request for {} {}", method, requestPath);
			filterChain.doFilter(request, response);
			return;
		}
		
		token = token.trim();
		
		log.debug("JWT Filter - Token found, validating...");
		
		try {

			if (!jwtTokenProvider.validateToken(token, "access")) {
				log.debug("JWT Filter - Invalid/expired access token for request: {} {}", method, requestPath);
				SecurityContextHolder.clearContext();
				filterChain.doFilter(request, response);
				return;
			}
			
			log.debug("JWT Filter - Token is valid");
			
			// get username from token (parser verifies signature again)
			String username = jwtTokenProvider.getUsername(token);
			
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			log.debug("JWT Filter - Loaded user details for: {}", userDetails.getUsername());
			
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					userDetails,
					null,
					userDetails.getAuthorities()
			);
			
			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			log.debug("JWT Filter - Authentication set in SecurityContext for user: {}", username);
				
		} catch (Exception ex) {
			// For invalid/malformed/tampered tokens, clear any existing authentication and proceed.
			// Protected endpoints will be rejected later by Spring Security.
			log.debug("JWT Filter - Token processing failed for {} {}: {}", method, requestPath, ex.getMessage());
			SecurityContextHolder.clearContext();
			filterChain.doFilter(request, response);
			return;
		}

		filterChain.doFilter(request, response);
	}
	
	private String getTokenFromRequest(HttpServletRequest request) {
		
		String bearerToken = request.getHeader("Authorization");
		
		if (StringUtils.hasText(bearerToken) && bearerToken.regionMatches(true, 0, "Bearer ", 0, 7)) {
			return bearerToken.substring(7);
		}
		return null;
	}

}
