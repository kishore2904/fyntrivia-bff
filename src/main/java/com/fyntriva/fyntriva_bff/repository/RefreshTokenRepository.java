package com.fyntriva.fyntriva_bff.repository;

import com.fyntriva.fyntriva_bff.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            update RefreshToken token
            set token.revokedAt = :revokedAt
            where token.familyId = :familyId
              and token.revokedAt is null
            """)
    int revokeActiveFamily(
            @Param("familyId") String familyId,
            @Param("revokedAt") Instant revokedAt
    );
}
