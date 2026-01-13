package com.sillyproject.security.service.impl;

import com.sillyproject.security.entity.RefreshToken;
import com.sillyproject.security.entity.User;
import com.sillyproject.security.entity.UserRole;
import com.sillyproject.security.pojo.LoginRequest;
import com.sillyproject.security.pojo.LoginResponse;
import com.sillyproject.security.pojo.SignupRequest;
import com.sillyproject.security.pojo.TokenRefreshResponse;
import com.sillyproject.security.pojo.ChangePasswordRequest;
import com.sillyproject.security.repository.RefreshTokenRepository;
import com.sillyproject.security.repository.RoleRepository;
import com.sillyproject.security.repository.UserRepository;
import com.sillyproject.security.repository.UserRoleRepository;
import com.sillyproject.security.security.JwtTokenProvider;
import com.sillyproject.security.security.TokenHashingService;
import com.sillyproject.security.service.AuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Value("${auth.max.sessions.per.user}")
    private int maxSessions;

    private AuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;
    private RefreshTokenRepository refreshTokenRepository;
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private RoleRepository roleRepository;
    private UserRoleRepository userRoleRepository;
    private TokenHashingService tokenHashingService;

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           JwtTokenProvider jwtTokenProvider,
                           RefreshTokenRepository refreshTokenRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           RoleRepository roleRepository,
                           UserRoleRepository userRoleRepository,
                           TokenHashingService tokenHashingService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userRoleRepository = userRoleRepository;
        this.tokenHashingService = tokenHashingService;
    }

    @Override
    public LoginResponse login(LoginRequest loginRequest) {
        log.info("Login attempt for user: {}", loginRequest.getUsernameOrEmail());
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new RuntimeException("User not found after authentication"));

        if (isSessionLimitReached(user)) {
            log.warn("Session limit reached for user: {}", username);
            throw new IllegalStateException("Maximum session limit reached for user.");
        }

        // Always mint tokens with the canonical username (not the login identifier),
        // otherwise refresh-token ownership checks can fail when logging in with email.
        String accessToken = jwtTokenProvider.generateAccessToken(username, user.getTokenVersion());
        String refreshToken = jwtTokenProvider.generateRefreshToken(username);
        RefreshToken refreshTokenObj = buildRefreshTokenObject(refreshToken, user);
        refreshTokenRepository.save(refreshTokenObj);

        log.info("Successful login for user: {}", username);
        LoginResponse response = new LoginResponse(accessToken, refreshToken, "Logged In successfully");
        return response;
    }

    private boolean isSessionLimitReached(User user) {
        long activeSessions = refreshTokenRepository.countByUserAndRevokedFalse(user);
        return activeSessions >= maxSessions;
    }

    private RefreshToken buildRefreshTokenObject(String token, User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(tokenHashingService.hash(token));
        refreshToken.setJti(jwtTokenProvider.getJti(token));
        refreshToken.setCreatedAt(new Date());
        refreshToken.setExpiryDate(jwtTokenProvider.getExpirationDate(token));
        return refreshToken;
    }

    @Override
    public TokenRefreshResponse refreshAccessToken(String refreshToken) throws Exception {
        log.debug("Refresh token request received");

        if (!jwtTokenProvider.validateToken(refreshToken, "refresh")) {
            log.warn("Invalid refresh token format or expired");
            throw new Exception("Invalid refresh token");
        }

        String username = jwtTokenProvider.getUsername(refreshToken);
        String refreshTokenHash = tokenHashingService.hash(refreshToken);

        // Validate refresh token exists in database
        Optional<RefreshToken> refreshTokenEntity = refreshTokenRepository.findByTokenHash(refreshTokenHash);
        if (refreshTokenEntity.isEmpty()) {
            log.warn("Refresh token not found in DB for user: {}", username);
            throw new Exception("Invalid refresh token");
        }

        RefreshToken current = refreshTokenEntity.get();

        // Reuse detection: a revoked refresh token being presented again is a strong theft signal.
        if (current.isRevoked()) {
            log.warn("Refresh token reuse detected for user: {}. Revoking all sessions.", username);
            revokeAllRefreshTokens(current.getUser());
            throw new Exception("Invalid refresh token");
        }

        // Verify token belongs to the user
        if (!current.getUser().getUsername().equals(username)) {
            log.warn("Token mismatch - token belongs to different user");
            throw new Exception("Token does not belong to user");
        }

        // Rotate refresh token on every successful refresh:
        // - revoke the presented refresh token
        // - mint a new refresh token and persist its hash
        current.setRevoked(true);
        current.setRevokedAt(new Date());
        refreshTokenRepository.save(current);

        String newAccessToken = jwtTokenProvider.generateAccessToken(username, current.getUser().getTokenVersion());
        // Absolute session lifetime: do NOT extend beyond the current refresh token's expiry.
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(username, current.getExpiryDate());

        RefreshToken newRefreshEntity = buildRefreshTokenObject(newRefreshToken, current.getUser());
        refreshTokenRepository.save(newRefreshEntity);

        log.info("Rotated refresh token and generated new access token for user: {}", username);
        return new TokenRefreshResponse(newAccessToken, newRefreshToken);
    }

    private void revokeAllRefreshTokens(User user) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUser(user);
        Date now = new Date();
        for (RefreshToken token : tokens) {
            if (!token.isRevoked()) {
                token.setRevoked(true);
                token.setRevokedAt(now);
                refreshTokenRepository.save(token);
            }
        }
    }

    @Override
    public void logoutSingleSession(String refreshToken) {
        String refreshTokenHash = tokenHashingService.hash(refreshToken);
        Optional<RefreshToken> tokenEntity = refreshTokenRepository.findByTokenHash(refreshTokenHash);
        if (tokenEntity.isPresent()) {
            RefreshToken token = tokenEntity.get();
            token.setRevoked(true);
            token.setRevokedAt(new Date());
            refreshTokenRepository.save(token);
            log.info("Session revoked for user: {}", token.getUser().getUsername());
        } else {
            log.warn("Attempt to logout with non-existent refresh token");
        }
    }

    @Override
    public void logoutAllSessions(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Invalidate all access tokens immediately
        user.setTokenVersion(user.getTokenVersion() + 1);
        user.setLastUpdatedBy(0);
        user.setLastUpdatedDate(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all refresh sessions so no new access tokens can be minted
        revokeAllRefreshTokens(user);

        log.info("All sessions revoked for user: {}", username);
    }

    @Override
    public void signup(SignupRequest signupRequest) {
        log.info("Signup attempt for username: {}, email: {}", signupRequest.getUsername(), signupRequest.getEmail());
        
        // Check if username already exists
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            log.warn("Signup failed - username already exists: {}", signupRequest.getUsername());
            throw new IllegalArgumentException("Username already exists");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            log.warn("Signup failed - email already exists: {}", signupRequest.getEmail());
            throw new IllegalArgumentException("Email already exists");
        }

        // Create new user
        User user = new User();
        user.setName(signupRequest.getName());
        user.setUsername(signupRequest.getUsername());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
        user.setCreatedBy(0); // System user
        user.setCreationDate(LocalDateTime.now());
        user.setLastUpdatedBy(0);
        user.setLastUpdatedDate(LocalDateTime.now());

        user = userRepository.save(user);


        // Create user role mapping
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(roleRepository.findByName("USER").orElseThrow(() -> new IllegalArgumentException("Role not found")));
        userRole.setEffectiveStartDate(LocalDateTime.now());
        userRole.setEffectiveEndDate(LocalDateTime.now().plusYears(100)); // Set far future date
        userRole.setCreatedBy(0);
        userRole.setCreationDate(LocalDateTime.now());
        userRole.setLastUpdatedBy(0);
        userRole.setLastUpdatedDate(LocalDateTime.now());

        userRoleRepository.save(userRole);
        log.info("User successfully registered: {}", signupRequest.getUsername());
    }

    @Override
    public void changePassword(String username, ChangePasswordRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request is required");
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid current password");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setTokenVersion(user.getTokenVersion() + 1); // invalidates all existing access tokens
        user.setLastUpdatedBy(0);
        user.setLastUpdatedDate(LocalDateTime.now());
        userRepository.save(user);

        // Revoke all refresh tokens so no new access tokens can be minted using old sessions.
        revokeAllRefreshTokens(user);

        log.info("Password changed and sessions revoked for user: {}", username);
    }

    @Override
    public void logoutCurrentUser(String username) {
        // In this system, "logout current user" is implemented as "logout all sessions"
        // because access tokens are stateless and we invalidate them via tokenVersion.
        logoutAllSessions(username);
    }
}
