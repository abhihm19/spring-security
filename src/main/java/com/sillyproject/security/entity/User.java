package com.sillyproject.security.entity;

import java.time.LocalDateTime;
import java.util.List;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class User {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;	
	private String name;
	@Column(nullable = false, unique = true)
	private String username;
	@Column(nullable = false, unique = true)
	private String email;
	@Column(nullable = false)
	private String password;

	/**
	 * Increment to invalidate all previously-issued access tokens for this user.
	 * Access tokens carry a "ver" claim and are rejected if it doesn't match this value.
	 */
	@Column(nullable = false)
	private int tokenVersion = 0;

	@OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
	private List<UserRole> roleMappings;

	private int createdBy;
	private LocalDateTime creationDate;
	private int lastUpdatedBy;
	private LocalDateTime lastUpdatedDate;

}
