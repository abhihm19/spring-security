package com.sillyproject.security.security;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint{

	private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);
	private final ObjectMapper objectMapper;
	
	public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		String requestPath = request.getRequestURI();
		String method = request.getMethod();
		String authHeader = request.getHeader("Authorization");
		
		log.error("AuthenticationEntryPoint triggered - {} {} - Error: {} - Auth Header present: {}", 
			method, 
			requestPath, 
			authException.getMessage(),
			authHeader != null);
		
		log.debug("Full authentication exception details:", authException);

		if (response.isCommitted()) {
			return;
		}

		response.resetBuffer();
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		Map<String, Object> body = new LinkedHashMap<>();
		body.put("timestamp", Instant.now().toString());
		body.put("status", 401);
		body.put("error", "Unauthorized");
		body.put("message", authException.getMessage());
		body.put("path", requestPath);
		body.put("method", method);

		objectMapper.writeValue(response.getOutputStream(), body);
	}

}
