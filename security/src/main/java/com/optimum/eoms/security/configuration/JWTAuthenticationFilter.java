package com.optimum.eoms.security.configuration;

import com.google.gson.Gson;
import com.optimum.eoms.common.exception.ApiErrorResponse;
import com.optimum.eoms.security.service.TokenAuthenticationService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

@Slf4j
public class JWTAuthenticationFilter extends GenericFilterBean {
  @Autowired TokenAuthenticationService tokenAuthenticationService;

  public JWTAuthenticationFilter(TokenAuthenticationService tokenAuthenticationService) {
    this.tokenAuthenticationService = tokenAuthenticationService;
  }

  @Override
  public void doFilter(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
    log.info("into doFilter()");
    HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
    HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
    try {
      Authentication authentication =
          tokenAuthenticationService.getAuthentication(httpServletRequest);
      if (authentication.isAuthenticated()) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } else {
        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }
      filterChain.doFilter(servletRequest, servletResponse);
    } catch (JwtException jwtException) {
      httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
      httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      ApiErrorResponse apiErrorResponse =
          new ApiErrorResponse.ApiErrorResponseBuilder()
              .withStatus(HttpStatus.UNAUTHORIZED)
              .withTimestamp(new Date())
              .withErrorCode(HttpStatus.UNAUTHORIZED.value())
              .withMessage(jwtException.getLocalizedMessage())
              .build();
      httpServletResponse.getWriter().print(new Gson().toJson(apiErrorResponse));
    }
  }
}
