package com.sillyproject.security.service;

import com.sillyproject.security.pojo.LoginRequest;
import com.sillyproject.security.pojo.LoginResponse;
import com.sillyproject.security.pojo.SignupRequest;

public interface AuthService {

    LoginResponse login(LoginRequest loginRequest);

    String refreshAccessToken(String refreshToken) throws Exception;

    void logoutSingleSession(String refreshToken);

    void logoutAllSessions(String username);

    void signup(SignupRequest signupRequest);
}
