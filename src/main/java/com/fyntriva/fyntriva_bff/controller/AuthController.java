package com.fyntriva.fyntriva_bff.controller;

import com.fyntriva.fyntriva_bff.dto.LoginRequest;
import com.fyntriva.fyntriva_bff.dto.LoginResponse;
import com.fyntriva.fyntriva_bff.service.AuthService;
import com.fyntriva.fyntriva_bff.service.AuthService.AuthResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String REFRESH_COOKIE_NAME = "refresh_token";
    private static final String REFRESH_COOKIE_PATH = "/api/auth";

    private final AuthService authService;
    private final boolean secureCookie;

    public AuthController(
            AuthService authService,
            @Value("${app.auth.refresh-cookie-secure:true}") boolean secureCookie
    ) {
        this.authService = authService;
        this.secureCookie = secureCookie;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        AuthResult result = authService.login(request);
        return withRefreshCookie(result);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshToken
    ) {
        AuthResult result = authService.refresh(refreshToken);
        return withRefreshCookie(result);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = REFRESH_COOKIE_NAME, required = false) String refreshToken
    ) {
        authService.logout(refreshToken);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, refreshCookie("", Duration.ZERO).toString())
                .build();
    }

    private ResponseEntity<LoginResponse> withRefreshCookie(AuthResult result) {
        return ResponseEntity.ok()
                .header(
                        HttpHeaders.SET_COOKIE,
                        refreshCookie(result.refreshToken(), result.refreshTokenMaxAge()).toString()
                )
                .body(result.response());
    }

    private ResponseCookie refreshCookie(String value, Duration maxAge) {
        return ResponseCookie.from(REFRESH_COOKIE_NAME, value)
                .httpOnly(true)
                .secure(secureCookie)
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
