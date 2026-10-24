package com.fyntriva.fyntriva_bff.repository;

import com.fyntriva.fyntriva_bff.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    boolean existsByEmail(String email);
}
