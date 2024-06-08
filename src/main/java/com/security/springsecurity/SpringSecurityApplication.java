package com.security.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurityApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityApplication.class, args);
  }

//  @Autowired
//  private CustomUserDetailsService userDetailsService;
//
//  @Bean
//  public PasswordEncoder passwordEncoder(){
//    return new BCryptPasswordEncoder();
//  }
//
//  @Bean
//  public DaoAuthenticationProvider authenticationProvider() {
//    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//    provider.setUserDetailsService(userDetailsService);
//    provider.setPasswordEncoder(passwordEncoder());
//    return provider;
//  }

}
