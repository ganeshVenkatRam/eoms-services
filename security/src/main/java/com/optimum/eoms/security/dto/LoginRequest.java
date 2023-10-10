package com.optimum.eoms.security.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * used to provide request params used for login API
 *
 * @param username
 * @param password
 */
public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
