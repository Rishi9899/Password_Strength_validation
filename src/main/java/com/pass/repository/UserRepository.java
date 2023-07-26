package com.pass.repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.pass.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

	User findByUsername(String username);

	
	boolean existsByUsername(String username);
	
	
	@Query("select u from User u where u.username=?1")
	User getUserByUsername(String username);
	   
	
}
