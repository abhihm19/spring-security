package com.sillyproject.security.service;

import com.sillyproject.security.pojo.LoginRequest;
import com.sillyproject.security.pojo.LoginResponse;
import com.sillyproject.security.pojo.SignupRequest;
import com.sillyproject.security.pojo.TokenRefreshResponse;
import com.sillyproject.security.pojo.ChangePasswordRequest;

public interface AuthService {

    LoginResponse login(LoginRequest loginRequest);

    TokenRefreshResponse refreshAccessToken(String refreshToken) throws Exception;

    void logoutSingleSession(String refreshToken);

    void logoutAllSessions(String username);

    void signup(SignupRequest signupRequest);

    void changePassword(String username, ChangePasswordRequest request);

    void logoutCurrentUser(String username);
}
