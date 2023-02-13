package com.xloop.resourceloop.authenticationservice.JPARepository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.xloop.resourceloop.authenticationservice.Model.User;

public interface UserRepository extends JpaRepository<User,Long> {
    
    public User findByEmail(String email);

    public List<User> findByRoleId(Long role_id);

}
