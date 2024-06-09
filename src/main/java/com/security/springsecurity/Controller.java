package com.security.springsecurity;

import com.security.springsecurity.Dto.LoginRequest;
import com.security.springsecurity.Dto.SignupRequest;
import com.security.springsecurity.Dto.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Controller {

  private final UserRepository userRepository;

  private final PasswordEncoder passwordEncoder;

  private final AuthenticationManager authenticationManager;


  @PostMapping("/signup")
  public String signup(@RequestBody SignupRequest signupRequest) {
    UserEntity user = UserEntity.builder()
      .username(signupRequest.getUsername())
      .password(passwordEncoder.encode(signupRequest.getPassword()))
      .build();

    userRepository.save(user);
    return "Registered successfully!";
  }

  @PostMapping("/login")
  public String login(@RequestBody LoginRequest loginRequest) {

    authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
    return JwtHelper.generateToken(loginRequest.getUsername());

  }

  @GetMapping("/test")
  public String test(@RequestHeader("Authorization") String token){
    return token;
  }

}

