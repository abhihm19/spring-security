package com.sillyproject.security.service.impl;

import com.sillyproject.security.entity.RefreshToken;
import com.sillyproject.security.entity.User;
import com.sillyproject.security.pojo.LoginRequest;
import com.sillyproject.security.pojo.LoginResponse;
import com.sillyproject.security.pojo.SignupRequest;
import com.sillyproject.security.repository.RefreshTokenRepository;
import com.sillyproject.security.repository.UserRepository;
import com.sillyproject.security.security.JwtTokenProvider;
import com.sillyproject.security.service.AuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {

    @Value("${auth.max.sessions.per.user}")
    private int maxSessions;

    private AuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;
    private RefreshTokenRepository refreshTokenRepository;
    private UserDetailsService userDetailsService;
    private UserRepository userRepository;

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           JwtTokenProvider jwtTokenProvider,
                           RefreshTokenRepository refreshTokenRepository,
                           UserDetailsService userDetailsService,
                           UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
    }

    @Override
    public LoginResponse login(LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsernameOrEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            Optional<User> user = userRepository.findByUsernameOrEmail(SecurityContextHolder.getContext().getAuthentication().getName(),
                    SecurityContextHolder.getContext().getAuthentication().getName());

            if (isSessionLimitReached(user.get())) {
                throw new IllegalStateException("Maximum session limit reached for user.");
            }

            String accessToken = jwtTokenProvider.generateAccessToken(loginRequest.getUsernameOrEmail());
            String refreshToken = jwtTokenProvider.generateRefreshToken(loginRequest.getUsernameOrEmail());
            RefreshToken refreshTokenObj = buildRefreshTokenObject(refreshToken, user.get());
            refreshTokenRepository.save(refreshTokenObj);

            LoginResponse response = new LoginResponse(accessToken, refreshToken, "Logged In successfully");
            return response;
        } catch (Exception e) {
            throw e;
        }
    }

    private boolean isSessionLimitReached(User user) {
        long activeSessions = refreshTokenRepository.countByUser(user);
        return activeSessions >= maxSessions;
    }

    private RefreshToken buildRefreshTokenObject(String token, User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(token);
        refreshToken.setCreatedAt(new Date());
        refreshToken.setExpiryDate(jwtTokenProvider.getExpirationDate(token));
        return refreshToken;
    }

    @Override
    public String refreshAccessToken(String refreshToken) throws Exception {

        if (!jwtTokenProvider.validateToken(refreshToken, "refresh")) {
            throw new Exception("Invalid refresh token");
        }

        String username = jwtTokenProvider.getUsername(refreshToken);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        String newAccessToken = jwtTokenProvider.generateAccessToken(authentication.getPrincipal().toString());
        return null;
    }

    @Override
    public void logoutSingleSession(String refreshToken) {

    }

    @Override
    public void logoutAllSessions(String username) {

    }

    @Override
    public void signup(SignupRequest signupRequest) {

    }
}
