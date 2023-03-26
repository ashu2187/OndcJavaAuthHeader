package com.faiyaz.ondc.authheaderjava;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;



@SpringBootApplication
@RestController
public class AuthheaderjavaApplication {
	

	public static void main(String[] args) {
		SpringApplication.run(AuthheaderjavaApplication.class, args);
		System.out.println("Program starts from here...");
		
		
	}

	@GetMapping("/")
	public String getHomePage() {
		return "Working Fine...!";
	}


}
