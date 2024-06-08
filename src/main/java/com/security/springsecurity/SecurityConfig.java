package com.security.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

//  @Autowired
//  AuthenticationProvider authenticationProvider;


  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf().disable()
      .authorizeHttpRequests()
      .requestMatchers("/signup", "/login").permitAll()
      .anyRequest().authenticated()
      .and()
      .httpBasic(Customizer.withDefaults());
    return http.build();
  }

//  @Bean
//  public UserDetailsService users() {
//    UserDetails user = User.builder()
//      .username("user")
//      .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
//      .roles("USER")
//      .build();
//    UserDetails admin = User.builder()
//      .username("admin")
//      .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
//      .roles("USER", "ADMIN")
//      .build();
//    return new InMemoryUserDetailsManager(user, admin);
//  }

//  @Autowired
//  public void configureGlobal(AuthenticationManagerBuilder auth) {
//    auth.authenticationProvider(authenticationProvider);
//  }

}
