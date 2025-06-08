package com.sillyproject.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sillyproject.security.entity.Role;


public interface RoleRepository extends JpaRepository<Role, Long> {
	
	Optional<Role> findByName(String name);

}
