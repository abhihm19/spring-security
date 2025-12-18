package com.sillyproject.security.repository;

import com.sillyproject.security.entity.RefreshToken;
import com.sillyproject.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findByUser(User user);

    void deleteByUser(User user);

    void deleteByTokenHash(String tokenHash);

    Long countByUser(User user);

    Long countByUserAndRevokedFalse(User user);
}
