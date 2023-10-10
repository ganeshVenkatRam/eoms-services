package com.optimum.eoms.security.dto;

import jakarta.validation.constraints.NotBlank;

public record PasswordRequest(@NotBlank String passwordToken) {}
