package com.sillyproject.security.security;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

import com.sillyproject.security.entity.Role;
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

	private UserRepository userRepository;
	private UserRoleRepository userRoleRepository;
	
	public CustomUserDetailsService(UserRepository userRepository, UserRoleRepository userRoleRepository) {
		this.userRepository = userRepository;
		this.userRoleRepository = userRoleRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
		User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
			.orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));

		List<String> activeRoles = userRoleRepository.findActiveRolesByUsername(user.getUsername(), LocalDate.now());

		List<GrantedAuthority> authorities = activeRoles.stream()
				.map(role -> new SimpleGrantedAuthority(role))
				.collect(Collectors.toList());


		return new org.springframework.security.core.userdetails.User(
        		user.getUsername(),
        		user.getPassword(),
				authorities
                );
	}

}
