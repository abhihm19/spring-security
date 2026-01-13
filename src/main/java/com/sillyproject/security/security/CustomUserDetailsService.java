package com.sillyproject.security.security;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sillyproject.security.repository.UserRoleRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.sillyproject.security.entity.User;
import com.sillyproject.security.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);
	
	private UserRepository userRepository;
	private UserRoleRepository userRoleRepository;
	
	public CustomUserDetailsService(UserRepository userRepository, UserRoleRepository userRoleRepository) {
		this.userRepository = userRepository;
		this.userRoleRepository = userRoleRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
		log.debug("Loading user details for: {}", usernameOrEmail);
		
		User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
			.orElseThrow(() -> {
				log.error("User not found with username or email: {}", usernameOrEmail);
				return new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail);
			});

		log.debug("User found in database: {}", user.getUsername());
		
		List<String> activeRoles = userRoleRepository.findActiveRolesByUsername(user.getUsername());
		log.info("Found {} active role(s) for user {}: {}", activeRoles.size(), user.getUsername(), activeRoles);

		List<GrantedAuthority> authorities = activeRoles.stream()
				.map(role -> {
					// Spring Security's hasRole() expects roles to be prefixed with "ROLE_"
					String roleName = role.startsWith("ROLE_") ? role : "ROLE_" + role;
					log.debug("Creating authority: {} (original role: {})", roleName, role);
					return new SimpleGrantedAuthority(roleName);
				})
				.collect(Collectors.toList());

		log.info("Created {} authority/authorities for user {}: {}", 
			authorities.size(), 
			user.getUsername(), 
			authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

		return new UserPrincipal(
				user.getUsername(),
				user.getPassword(),
				user.getTokenVersion(),
				authorities
		);
	}

}
