package com.fyntriva.fyntriva_bff.service;

import com.fyntriva.fyntriva_bff.auth.JwtService;
import com.fyntriva.fyntriva_bff.dto.LoginRequest;
import com.fyntriva.fyntriva_bff.dto.LoginResponse;
import com.fyntriva.fyntriva_bff.dto.UserResponse;
import com.fyntriva.fyntriva_bff.entity.User;
import com.fyntriva.fyntriva_bff.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.Locale;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            RefreshTokenService refreshTokenService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    public AuthResult login(LoginRequest request) {
        if (request == null || isBlank(request.email()) || isBlank(request.password())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email and password are required");
        }

        User user = userRepository.findByEmail(request.email().trim().toLowerCase(Locale.ROOT))
                .orElseThrow(this::invalidCredentials);

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw invalidCredentials();
        }
        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User account is inactive");
        }

        String accessToken = jwtService.generateToken(user);
        RefreshTokenService.IssuedToken refresh = refreshTokenService.createSession(user);
        return new AuthResult(loginResponse(user, accessToken), refresh.token(), refresh.maxAge());
    }

    public AuthResult refresh(String refreshToken) {
        RefreshTokenService.IssuedToken refresh = refreshTokenService.rotate(refreshToken);
        User user = refresh.user();
        String accessToken = jwtService.generateToken(user);
        return new AuthResult(loginResponse(user, accessToken), refresh.token(), refresh.maxAge());
    }

    public void logout(String refreshToken) {
        refreshTokenService.revoke(refreshToken);
    }

    private LoginResponse loginResponse(User user, String accessToken) {
        return new LoginResponse(
                accessToken,
                "Bearer",
                jwtService.getExpirationSeconds(),
                UserResponse.from(user)
        );
    }

    private ResponseStatusException invalidCredentials() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record AuthResult(LoginResponse response, String refreshToken, Duration refreshTokenMaxAge) {
    }
}
