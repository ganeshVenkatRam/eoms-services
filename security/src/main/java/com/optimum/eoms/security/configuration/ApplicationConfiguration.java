package com.optimum.eoms.security.configuration;

import com.optimum.eoms.security.service.impl.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@Slf4j
public class ApplicationConfiguration {

  @Value("${spring.security.user.name}")
  private String username;

  @Value("${spring.security.batch.user.name}")
  private String batchUsername;

  @Value("${spring.security.user.password}")
  private String password;

  @Value("${spring.security.batch.user.password}")
  private String batchPassword;

  @Autowired UserDetailsServiceImpl userDetailsService;

  @Autowired PasswordEncoderConfiguration passwordEncoderConfiguration;

  @Bean
  public AuthenticationProvider appAuthenticationProvider() {
    log.info("into authenticationProvider()");
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoderConfiguration.passwordEncoder());
    return authProvider;
  }

  @Bean
  protected AuthenticationManager swaggerAuthenticationManager() throws Exception {
    ProviderManager manager = new ProviderManager(swaggerAuthenticationProvider());
    return manager;
  }

  @Bean
  UserDetailsService userDetailsSwaggerService() {
    UserDetails user = User.withUsername(username)
            .password(passwordEncoderConfiguration.passwordEncoder().encode(password))
            .roles("")
            .build();

    return new InMemoryUserDetailsManager(user);
  }
  @Bean
  public AuthenticationProvider swaggerAuthenticationProvider() {
    log.info("into authenticationProvider()");
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsSwaggerService());
    authProvider.setPasswordEncoder(passwordEncoderConfiguration.passwordEncoder());
    return authProvider;
  }
  @Bean
  UserDetailsService userDetailsBatchService() {
    UserDetails userDetails =
            User.withUsername(batchUsername)
                    .password(passwordEncoderConfiguration.passwordEncoder().encode(batchPassword))
                    .roles("")
                    .build();

    return new InMemoryUserDetailsManager(userDetails);
  }

  @Bean
  public AuthenticationProvider batchAuthenticationProvider(){
    log.info("into batchAuthenticationProvider()");
    DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setUserDetailsService(userDetailsBatchService());
    daoAuthenticationProvider.setPasswordEncoder(passwordEncoderConfiguration.passwordEncoder());
    return daoAuthenticationProvider;
  }

  @Bean
  protected AuthenticationManager batchAuthenticationManager() {
    ProviderManager manager = new ProviderManager(batchAuthenticationProvider());
    return manager;
  }

  @Primary
  @Bean
  protected AuthenticationManager appAuthenticationManager() throws Exception {
    ProviderManager manager = new ProviderManager(appAuthenticationProvider());
    return manager;
  }
  @Bean
  public DelegatedAuthenticationEntryPoint authenticationEntryPoint() {
    return new DelegatedAuthenticationEntryPoint();
  }
}
