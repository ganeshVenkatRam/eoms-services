package com.optimum.eoms.security.dto;

import java.util.Map;

/**
 * used to provide response for login API
 *
 * @param tokenMap
 */
public record LoginResponse(Map<String, String> tokenMap) {}
