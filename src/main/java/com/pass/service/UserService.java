package com.pass.service;

import org.springframework.stereotype.Service;

import com.pass.repository.UserRepository;

@Service
public class UserService {

private final UserRepository userRepository;

public UserService(UserRepository userRepository) {
this.userRepository = userRepository;
}

public boolean isUsernameTaken(String username) {
return userRepository.existsByUsername(username);
}


public boolean isStrongPassword(String password) {
String passwordRegex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$";
return password.matches(passwordRegex);
}


}