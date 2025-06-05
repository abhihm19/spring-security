package com.sillyproject.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ObjectController {
	
	@GetMapping("/public_route")
	public String publicMethod() {
		return "Public api endpoint";
	}
	
	@GetMapping("/role1")
	public String role1() {
		return "Role1 api endpoint";
	}
	
	@GetMapping("/role2")
	public String role2() {
		return "Role2 api endpoint";
	}

}
