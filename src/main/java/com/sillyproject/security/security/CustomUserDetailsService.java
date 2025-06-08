package com.sillyproject.security.security;

import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.sillyproject.security.model.User;
import com.sillyproject.security.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private UserRepository userRepository;
	
	public CustomUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
		User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
			.orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));
		System.out.println(user);
		return new org.springframework.security.core.userdetails.User(
        		user.getUsername(),
        		user.getPassword(),
                user.getRoles()
                	.stream()
                    .map((role) -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList())
                );
	}

}
