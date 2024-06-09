package com.security.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private CustomUserDetailsService customUserDetailsService;


  @PostMapping("/signup")
  public String signup(@RequestBody UserEntity userEntity) {
    userRepository.save(userEntity);
    return "Registered successfully!";
  }

  @PostMapping("/login")
  public String login(@RequestBody UserEntity userEntity) {
    UserDetails userDetails = customUserDetailsService.loadUserByUsername(userEntity.getUsername());
    if (userDetails.getPassword().equals(userEntity.getPassword())) {
      return "Login successfully!";
    } else {
      throw new UsernameNotFoundException("Invalid username or password");
    }
  }


}

