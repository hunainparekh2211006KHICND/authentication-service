
package com.xloop.resourceloop.authenticationservice.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.xloop.resourceloop.authenticationservice.JPARepository.UserRepository;
import com.xloop.resourceloop.authenticationservice.Model.User;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserRepository userRepo;

    @GetMapping("/all")
    public List<User> getAllUsers(){
        return userRepo.findAll();
    }

    @GetMapping("/getByRole/{role_id}")
    public List<User> getByRole(@PathVariable Long role_id){
        return userRepo.findByRoleId(role_id);
    }

    @GetMapping("/{id}")
    public User getById(@PathVariable Long id){
        return userRepo.findById(id).orElse(null);
    }
}
