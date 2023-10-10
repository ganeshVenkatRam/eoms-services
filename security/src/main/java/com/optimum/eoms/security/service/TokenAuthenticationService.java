package com.optimum.eoms.security.service;

import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONException;
import org.springframework.security.core.Authentication;

public interface TokenAuthenticationService {
  Authentication getAuthentication(HttpServletRequest request) throws JSONException;
}
