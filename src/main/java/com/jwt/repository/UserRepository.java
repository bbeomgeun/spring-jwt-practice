package com.jwt.repository;

import com.jwt.practice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    public User findByUserName(String userName);
}
