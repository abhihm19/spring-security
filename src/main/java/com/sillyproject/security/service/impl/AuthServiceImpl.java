package com.sillyproject.security.service.impl;

import com.sillyproject.security.entity.RefreshToken;
import com.sillyproject.security.entity.Role;
import com.sillyproject.security.entity.User;
import com.sillyproject.security.entity.UserRole;
import com.sillyproject.security.pojo.LoginRequest;
import com.sillyproject.security.pojo.LoginResponse;
import com.sillyproject.security.pojo.SignupRequest;
import com.sillyproject.security.repository.RefreshTokenRepository;
import com.sillyproject.security.repository.RoleRepository;
import com.sillyproject.security.repository.UserRepository;
import com.sillyproject.security.repository.UserRoleRepository;
import com.sillyproject.security.security.JwtTokenProvider;
import com.sillyproject.security.service.AuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
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

    public AuthServiceImpl(AuthenticationManager authenticationManager,
                           JwtTokenProvider jwtTokenProvider,
                           RefreshTokenRepository refreshTokenRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           RoleRepository roleRepository,
                           UserRoleRepository userRoleRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userRoleRepository = userRoleRepository;
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
        String accessToken = jwtTokenProvider.generateAccessToken(username);
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
        refreshToken.setToken(token);
        refreshToken.setCreatedAt(new Date());
        refreshToken.setExpiryDate(jwtTokenProvider.getExpirationDate(token));
        return refreshToken;
    }

    @Override
    public String refreshAccessToken(String refreshToken) throws Exception {
        log.debug("Refresh token request received");

        if (!jwtTokenProvider.validateToken(refreshToken, "refresh")) {
            log.warn("Invalid refresh token format or expired");
            throw new Exception("Invalid refresh token");
        }

        String username = jwtTokenProvider.getUsername(refreshToken);

        // Validate refresh token exists in database and is not revoked
        Optional<RefreshToken> refreshTokenEntity = refreshTokenRepository.findByToken(refreshToken);
        if (refreshTokenEntity.isEmpty() || refreshTokenEntity.get().isRevoked()) {
            log.warn("Invalid or revoked refresh token for user: {}", username);
            throw new Exception("Invalid or revoked refresh token");
        }

        // Verify token belongs to the user
        if (!refreshTokenEntity.get().getUser().getUsername().equals(username)) {
            log.warn("Token mismatch - token belongs to different user");
            throw new Exception("Token does not belong to user");
        }

        // Generate new access token using the username (not principal.toString())
        String newAccessToken = jwtTokenProvider.generateAccessToken(username);
        log.info("New access token generated for user: {}", username);
        return newAccessToken;
    }

    @Override
    public void logoutSingleSession(String refreshToken) {
        Optional<RefreshToken> tokenEntity = refreshTokenRepository.findByToken(refreshToken);
        if (tokenEntity.isPresent()) {
            RefreshToken token = tokenEntity.get();
            token.setRevoked(true);
            refreshTokenRepository.save(token);
            log.info("Session revoked for user: {}", token.getUser().getUsername());
        } else {
            log.warn("Attempt to logout with non-existent refresh token");
        }
    }

    @Override
    public void logoutAllSessions(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            List<RefreshToken> tokens = refreshTokenRepository.findByUser(user.get());
            int revokedCount = 0;
            for (RefreshToken token : tokens) {
                if (!token.isRevoked()) {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                    revokedCount++;
                }
            }
            log.info("All sessions revoked for user: {} ({} sessions)", username, revokedCount);
        } else {
            log.warn("Attempt to logout all sessions for non-existent user: {}", username);
        }
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

        // Assign default role "USER" if it exists, otherwise create it
        Role defaultRole = roleRepository.findByName("USER")
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName("USER");
                    role.setActive(true);
                    role.setCreatedBy(0);
                    role.setCreationDate(LocalDateTime.now());
                    role.setLastUpdatedBy(0);
                    role.setLastUpdatedDate(LocalDateTime.now());
                    return roleRepository.save(role);
                });

        // Create user role mapping
        UserRole userRole = new UserRole();
        userRole.setUser(user);
        userRole.setRole(defaultRole);
        userRole.setEffectiveStartDate(LocalDateTime.now());
        userRole.setEffectiveEndDate(LocalDateTime.now().plusYears(100)); // Set far future date
        userRole.setCreatedBy(0);
        userRole.setCreationDate(LocalDateTime.now());
        userRole.setLastUpdatedBy(0);
        userRole.setLastUpdatedDate(LocalDateTime.now());

        userRoleRepository.save(userRole);
        log.info("User successfully registered: {}", signupRequest.getUsername());
    }
}
