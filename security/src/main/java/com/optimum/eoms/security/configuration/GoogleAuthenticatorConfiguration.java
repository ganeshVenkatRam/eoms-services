package com.optimum.eoms.security.configuration;

import com.optimum.eoms.security.repository.CredentialRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class GoogleAuthenticatorConfiguration {

  private final CredentialRepository credentialRepository;

  @Bean
  public GoogleAuthenticator gAuth() {
    GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder googleAuthenticatorConfigBuilder =
        new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
    googleAuthenticatorConfigBuilder.setWindowSize(1);
    GoogleAuthenticator googleAuthenticator =
        new GoogleAuthenticator(googleAuthenticatorConfigBuilder.build());
    googleAuthenticator.setCredentialRepository(credentialRepository);
    return googleAuthenticator;
  }
}
