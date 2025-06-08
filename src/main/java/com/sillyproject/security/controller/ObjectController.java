package com.sillyproject.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ObjectController {
	
	@GetMapping("/public_route")
	public String publicMethod() {
		return "Public api endpoint";
	}

	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/admin")
	public String role1() {
		return "Admin api endpoint";
	}

	@PreAuthorize("hasRole('USER')")
	@GetMapping("/user")
	public String role2() {
		return "User api endpoint";
	}

}
