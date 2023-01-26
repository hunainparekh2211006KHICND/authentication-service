package com.xloop.resourceloop.authenticationservice;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
// import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.json.AutoConfigureJsonTesters;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xloop.resourceloop.authenticationservice.Classes.Auth;
import com.xloop.resourceloop.authenticationservice.Controller.AuthController;
import com.xloop.resourceloop.authenticationservice.JPARepository.UserRepository;
import com.xloop.resourceloop.authenticationservice.Model.User;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.http.MediaType;

@AutoConfigureJsonTesters
@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationServiceApplicationTests {

	@Mock
	private UserRepository userRepo;

	@InjectMocks
	private AuthController authController;

	private MockMvc mvc;

	private JacksonTester<User> jsonUser;
	private JacksonTester<Auth> jsonAuth;

	@BeforeEach
	public void setUp(){
		JacksonTester.initFields(this, new ObjectMapper());
		mvc = MockMvcBuilders.standaloneSetup(authController).build();
	}

	@Test
	public void canRegisterSuccessfully() throws Exception {
		User user = new User("Hunain","Parekh","hunain@hunain.com","12345");
		mvc.perform(post("/auth/register")
			.contentType(MediaType.APPLICATION_JSON)
			.content(jsonUser.write(user).getJson()))
			.andExpect(status().isOk())
			.andExpect(content().string("User Registered"));
	}

	@Test
	public void canNotRegisterSuccessfully() throws Exception {
		User user = new User("Hunain","Parekh");
		mvc.perform(post("/auth/register")
			.contentType(MediaType.APPLICATION_JSON)
			.content(jsonUser.write(user).getJson()))
			.andExpect(status().isBadRequest())
			.andExpect(content().string("All feilds Required"));
	} 

	@Test
	public void userAlreadyExist() throws Exception {
		User user = new User("Hunain","Parekh","hunain@hunain.com","12345");
		when(userRepo.findByEmail(user.getEmail())).thenReturn(user);
		mvc.perform(post("/auth/register")
			.contentType(MediaType.APPLICATION_JSON)
			.content(jsonUser.write(user).getJson()))
			.andExpect(status().isConflict())
			.andExpect(content().string("User Already Exist"));
	}
	
	@Test
	public void canLoginSuccessfully() throws Exception{
		User user = new User("Hunain","Parekh","hunain@hunain.com","Hunain123@");
		Auth auth = new Auth("hunain@hunain.com","Hunain123@");
		when(userRepo.findByEmailAndPassword(auth.getEmail(),auth.getPassword())).thenReturn(user);
		mvc.perform(post("/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content(jsonAuth.write(auth).getJson()))
			.andExpect(status().isOk())
			.andExpect(content().json(jsonUser.write(user).getJson()));
	}
	
	@Test 
	public void canNotLoginSuccessfullyDueToIncorrectPassword() throws Exception{
	User user = new User("Hunain","Parekh","hunain@hunain.com","Hunain123@");
	Auth auth = new Auth("hunain@hunain.com","commander_in_chief@123");
	when(userRepo.findByEmailAndPassword(auth.getEmail(), auth.getPassword())).thenReturn(null);
	mvc.perform(post("/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content(jsonAuth.write(auth).getJson()))
			.andExpect(status().isNotFound());
	}

	@Test 
	public void canNotLoginSuccessfullyDueToIncorrectEmail() throws Exception{
	User user = new User("Hunain","Parekh","hunain@hunain.com","Hunain123@");
	Auth auth = new Auth("hunain@hunain.com.pk","Hunain123@");
	when(userRepo.findByEmailAndPassword(auth.getEmail(), auth.getPassword())).thenReturn(null);
	mvc.perform(post("/auth/login")
			.contentType(MediaType.APPLICATION_JSON)
			.content(jsonAuth.write(auth).getJson()))
			.andExpect(status().isNotFound());
	}

	@Test
	public void test(){
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

		String plantext = "Zia";
		System.out.println("Encrypted Key: "+encryptor.encrypt(plantext));
	}
}
