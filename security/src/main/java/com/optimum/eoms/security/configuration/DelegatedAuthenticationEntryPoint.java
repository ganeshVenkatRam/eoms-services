package com.optimum.eoms.security.configuration;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.servlet.HandlerExceptionResolver;

public class DelegatedAuthenticationEntryPoint implements AuthenticationEntryPoint {
  @Qualifier("handlerExceptionResolver")
  @Autowired
  private HandlerExceptionResolver resolver;

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException) {
    resolver.resolveException(request, response, null, authException);
  }
}
