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
		
		// Defensive: ensure no authentication "leaks" between requests/threads
		SecurityContextHolder.clearContext();
		
		boolean isPublicEndpoint = isPublicEndpoint(requestPath, method);
		
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
			// validate token (signature/type/expiry)
			if (!jwtTokenProvider.validateToken(token, "access")) {
				log.warn("JWT Filter - Token validation failed for request: {} {}", method, requestPath);
				
				// For public endpoints: ignore invalid token and proceed unauthenticated
				if (isPublicEndpoint) {
					filterChain.doFilter(request, response);
					return;
				}
				
				// For protected endpoints: reject immediately
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired access token");
				return;
			}
			
			log.debug("JWT Filter - Token is valid");
			
			// get username from token (parser verifies signature again)
			String username = jwtTokenProvider.getUsername(token);
			log.info("JWT Filter - Extracted username from token: {}", username);
			
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			log.info("JWT Filter - Loaded user details for: {}, authorities: {}", 
				userDetails.getUsername(), 
				userDetails.getAuthorities());
			
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
					userDetails,
					null,
					userDetails.getAuthorities()
			);
			
			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			log.info("JWT Filter - Authentication set in SecurityContext for user: {} with authorities: {}", 
				username, 
				userDetails.getAuthorities());
				
		} catch (Exception ex) {
			// For invalid/malformed/tampered tokens, log and clear any existing authentication
			log.error("JWT Filter - Token processing failed for {} {}: {}", method, requestPath, ex.getMessage());
			log.debug("JWT Filter - Full exception details:", ex);
			
			// Clear any authentication that might have been set
			SecurityContextHolder.clearContext();
			if (isPublicEndpoint) {
				// Ignore and proceed unauthenticated
				filterChain.doFilter(request, response);
				return;
			}
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid access token");
			return;
		}

		filterChain.doFilter(request, response);
	}
	
	private boolean isPublicEndpoint(String path, String method) {
		if (path == null) return false;
		if (path.startsWith("/api/v1/auth/")) return true;
		return "GET".equalsIgnoreCase(method) && "/api/v1/public_route".equals(path);
	}
	
	private String getTokenFromRequest(HttpServletRequest request) {
		
		String bearerToken = request.getHeader("Authorization");
		
		if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7, bearerToken.length());
		}
		return null;
	}

}
