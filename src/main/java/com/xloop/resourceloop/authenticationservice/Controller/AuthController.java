package com.xloop.resourceloop.authenticationservice.Controller;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.xloop.resourceloop.authenticationservice.Classes.Auth;
import com.xloop.resourceloop.authenticationservice.JPARepository.UserRepository;
import com.xloop.resourceloop.authenticationservice.Model.User;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthController {
    @Autowired
    private UserRepository userRepo;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user){
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword("resourceloop"); // encryptor's private key
        config.setAlgorithm("PBEWithMD5AndDES");
        config.setKeyObtentionIterations("1000");
        config.setPoolSize("1");
        config.setProviderName("SunJCE");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setStringOutputType("base64");
        encryptor.setConfig(config);
        
        if(user.getFirst_name() != null && user.getEmail() != null && user.getPassword() != null){
            User userExists = userRepo.findByEmail(user.getEmail());
            if(userExists != null){
                return ResponseEntity.status(409).body("User Already Exist");
            }
            String encrypt_password = encryptor.encrypt(user.getPassword());
            user.setPassword(encrypt_password);
            userRepo.save(user);
            return ResponseEntity.ok("User Registered");
        }
        else{
            return ResponseEntity.status(400).body("All feilds Required");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody Auth auth){
        User user = userRepo.findByEmailAndPassword(auth.getEmail(), auth.getPassword());
        if(user == null){
            return ResponseEntity.status(404).body(null);
        }
        return ResponseEntity.status(200).body(user);
    }

    @PostMapping("/forgetpassword/{id}")
    public ResponseEntity<String> resetPassword(@PathVariable Long id ,@RequestBody String new_password){
        User user = userRepo.findById(id).orElse(null);
        user.setPassword(new_password);
        userRepo.save(user);
        return ResponseEntity.status(200).body("Password Updated Successfully");
    } 
}
