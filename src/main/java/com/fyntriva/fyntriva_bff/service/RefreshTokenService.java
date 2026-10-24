package com.fyntriva.fyntriva_bff.service;

import com.fyntriva.fyntriva_bff.entity.RefreshToken;
import com.fyntriva.fyntriva_bff.entity.User;
import com.fyntriva.fyntriva_bff.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final int TOKEN_BYTES = 32;
    private static final int MAX_TOKEN_LENGTH = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final long expirationSeconds;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            @Value("${app.auth.refresh-token-expiration-seconds}") long expirationSeconds
    ) {
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Refresh token expiration must be greater than zero");
        }
        this.refreshTokenRepository = refreshTokenRepository;
        this.expirationSeconds = expirationSeconds;
    }

    @Transactional
    public IssuedToken createSession(User user) {
        Instant expiresAt = Instant.now().plusSeconds(expirationSeconds);
        return createToken(user, UUID.randomUUID().toString(), expiresAt);
    }

    @Transactional(noRollbackFor = ResponseStatusException.class)
    public IssuedToken rotate(String rawToken) {
        if (rawToken == null || rawToken.isBlank() || rawToken.length() > MAX_TOKEN_LENGTH) {
            throw invalidRefreshToken();
        }

        RefreshToken current = refreshTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(this::invalidRefreshToken);
        Instant now = Instant.now();

        if (current.getRevokedAt() != null) {
            refreshTokenRepository.revokeActiveFamily(current.getFamilyId(), now);
            throw invalidRefreshToken();
        }
        if (!current.getExpiresAt().isAfter(now)) {
            refreshTokenRepository.revokeActiveFamily(current.getFamilyId(), now);
            throw invalidRefreshToken();
        }

        User user = current.getUser();
        if (!user.isActive()) {
            refreshTokenRepository.revokeActiveFamily(current.getFamilyId(), now);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User account is inactive");
        }

        String nextRawToken = generateRawToken();
        String nextHash = hash(nextRawToken);
        current.revoke(now, nextHash);
        refreshTokenRepository.saveAndFlush(current);

        RefreshToken next = new RefreshToken(
                user,
                current.getFamilyId(),
                nextHash,
                current.getExpiresAt()
        );
        refreshTokenRepository.save(next);
        return new IssuedToken(nextRawToken, user, Duration.between(now, current.getExpiresAt()));
    }

    @Transactional
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank() || rawToken.length() > MAX_TOKEN_LENGTH) {
            return;
        }
        refreshTokenRepository.findByTokenHash(hash(rawToken)).ifPresent(token ->
                refreshTokenRepository.revokeActiveFamily(token.getFamilyId(), Instant.now())
        );
    }

    private IssuedToken createToken(User user, String familyId, Instant expiresAt) {
        String rawToken = generateRawToken();
        RefreshToken token = new RefreshToken(user, familyId, hash(rawToken), expiresAt);
        refreshTokenRepository.save(token);
        return new IssuedToken(rawToken, user, Duration.between(Instant.now(), expiresAt));
    }

    private String generateRawToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private ResponseStatusException invalidRefreshToken() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token is invalid or expired");
    }

    public record IssuedToken(String token, User user, Duration maxAge) {
    }
}
