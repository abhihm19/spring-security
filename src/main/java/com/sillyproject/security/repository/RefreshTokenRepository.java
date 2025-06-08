package com.sillyproject.security.repository;

import com.sillyproject.security.entity.RefreshToken;
import com.sillyproject.security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUser(User user);

    void deleteByUser(User user);

    void deleteByToken(String token);

    Integer countByUser(User user);
}
