package com.pass.main.controller;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pass.exception.ResourceNotFoundException;
import com.pass.model.User;
import com.pass.repository.UserRepository;
import com.pass.service.UserService;


@RestController
@RequestMapping("/api")
public class UserController {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private UserService userService ;
	
	@Autowired
    private BCryptPasswordEncoder passwordEncoder;
	
	
	
	 

    @PostMapping("/login")
    public String login(@RequestBody User user) {
        String username = user.getUsername();
        String password = user.getPassword();

        User user1 = userRepository.findByUsername(username);

        if (user1 == null) {
            return "User not found";
        }

        if (!passwordEncoder.matches(password, user1.getPassword())) {
            return "Invalid password";
        }
        // Save the user with a strong password
        

        return "Login successful";
    }

    @GetMapping("/users")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


//    

    

    @PostMapping("/register")
    public ResponseEntity<?> createUser(@RequestBody User user) {
        String password = user.getPassword();
        String username = user.getUsername();

        if (userService.isUsernameTaken(username)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username already exists");
        }

        boolean hasUppercase = password.matches(".*[A-Z].*");
        boolean hasSpecialChar = hasSpecialCharacter(password);
        boolean hasNumber = password.matches(".*\\d.*");
        boolean isLongEnough = password.length() >= 8;

        int strengthPercentage = 0;
        int totalConditions = 4;

        if (hasUppercase) strengthPercentage++;
        if (hasSpecialChar) strengthPercentage++;
        if (hasNumber) strengthPercentage++;
        if (isLongEnough) strengthPercentage++;

        // Calculate the percentage of password strength
        int percentage = (int) ((strengthPercentage / (double) totalConditions) * 100);

        if (percentage < 100) {
            String errorMessage = "Weak password. Password must meet the following criteria:\n";
            if (!hasUppercase) {
                errorMessage += "- Password must contain at least one uppercase letter.\n";
            }
            if (!hasSpecialChar) {
                errorMessage += "- Password must contain at least one special character.\n";
            }
            if (!hasNumber) {
                errorMessage += "- Password must contain at least one number.\n";
            }
            if (!isLongEnough) {
                errorMessage += "- Password must be at least 8 characters long.\n";
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage + percentage+"%");
        }
        
       

        // Password is strong, proceed with saving the user to the repository
       
        
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        User savedUser = userRepository.save(user);

        return ResponseEntity.status(HttpStatus.OK).body("Strong password. Password is secure and meets all the requirements. Strength: " + percentage + "%");
    }

    // Helper method to check for the presence of at least one special character
    private boolean hasSpecialCharacter(String password) {
        String specialCharRegex = "[!@#\\$%\\^&*()_+\\-=\\[\\]{};':\"\\\\|,\\.<>/\\?]";
        Pattern pattern = Pattern.compile(specialCharRegex);
        Matcher matcher = pattern.matcher(password);
        return matcher.find();
    }



    @PutMapping("/users/{id}")
    public ResponseEntity<User> updateUser(@PathVariable(value = "id") Long userId, @RequestBody User userDetails) {
        User user = null;
		try {
			user = userRepository.findById(userId)
			        .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
		} catch (ResourceNotFoundException e) {
			e.printStackTrace();
		}

        user.setUsername(userDetails.getUsername());
        user.setPassword(userDetails.getPassword());

        final User updatedUser = userRepository.save(user);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/users/{id}")
    public Map<String, Boolean> deleteUser(@PathVariable(value = "id") Long userId) {
        User user = null;
		try {
			user = userRepository.findById(userId)
			        .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));
		} catch (ResourceNotFoundException e) {
			e.printStackTrace();
		}

        userRepository.delete(user);
        Map<String, Boolean> response = new HashMap<>();
        response.put("deleted", Boolean.TRUE);
        return response;
    }

}


