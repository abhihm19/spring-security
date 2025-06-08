package com.sillyproject.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sillyproject.security.entity.User;


public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByEmail(String email);

	Optional<User> findByUsername(String username);

	Optional<User> findByUsernameOrEmail(String username, String email);

	Boolean existsByEmail(String email);

	Boolean existsByUsername(String username);
	
}
