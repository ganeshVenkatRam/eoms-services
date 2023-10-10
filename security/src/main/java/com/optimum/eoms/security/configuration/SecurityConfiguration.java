package com.optimum.eoms.security.configuration;

import static org.springframework.security.config.Customizer.withDefaults;

import com.optimum.eoms.security.service.TokenAuthenticationService;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/** used to provide security configuration for authentication and authorization */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Slf4j
public class SecurityConfiguration {

  @Autowired ApplicationConfiguration applicationConfiguration;

  @Autowired TokenAuthenticationService tokenAuthenticationService;

  @Autowired AuthenticationEntryPoint authenticationEntryPoint;

  @Autowired LogoutHandler logoutHandler;

  @Bean
  @Order(1)
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.cors()
        .and()
        .csrf()
        .disable()
        // TODO:For now we are matching with endpoints /api/** and perform authentication but later
        // whatever endpoint we have, that has to pass the security check.
        .securityMatcher(AntPathRequestMatcher.antMatcher("/api/**"))
        .authorizeHttpRequests(
            auth -> {
              auth.requestMatchers(
                      AntPathRequestMatcher.antMatcher("/api/auth/**"),
                      AntPathRequestMatcher.antMatcher("/api/user/forgotpassword"))
                  .permitAll();
              auth.anyRequest().authenticated();
            })
        .authenticationManager(applicationConfiguration.appAuthenticationManager())
        .addFilterBefore(
            new JWTAuthenticationFilter(tokenAuthenticationService),
            UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint);
    http.logout()
        .logoutUrl("/api/auth/logout")
        .addLogoutHandler(logoutHandler)
        .logoutSuccessHandler(
            (request, response, authentication) -> {
              if (response.getStatus() == 200) {
                SecurityContextHolder.clearContext();
              }
            });

    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
    return http.securityMatcher("/swagger-ui/**")
        .authorizeHttpRequests(
            auth -> {
              auth.anyRequest().authenticated();
            })
        .httpBasic(withDefaults())
        .authenticationManager(applicationConfiguration.swaggerAuthenticationManager())
        .build();
  }

  @Bean
  @Order(3)
  SecurityFilterChain BatchSecurityFilterChain(HttpSecurity http) throws Exception {
    return http.securityMatcher("/batch/**")
        .authorizeHttpRequests(
            auth -> {
              auth.anyRequest().authenticated();
            })
        .httpBasic(withDefaults())
        .authenticationManager(applicationConfiguration.batchAuthenticationManager())
        .build();
  }

  @Bean
  public CorsFilter corsFilter() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    final CorsConfiguration config = new CorsConfiguration();
    // TODO:For now we are allowing all origin but later we need to restrict to our application url.
    config.setAllowedOrigins(Arrays.asList("*"));
    config.setAllowedMethods(
        Arrays.asList(
            HttpMethod.GET.name(),
            HttpMethod.POST.name(),
            HttpMethod.PUT.name(),
            HttpMethod.DELETE.name(),
            HttpMethod.OPTIONS.name(),
            HttpMethod.PATCH.name()));
    config.setAllowedHeaders(Collections.singletonList("*"));
    config.setAllowCredentials(false);
    config.setExposedHeaders(List.of(HttpHeaders.CONTENT_DISPOSITION));
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
  }
}
