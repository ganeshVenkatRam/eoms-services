package com.optimum.eoms.security.service;

import com.optimum.eoms.model.user.dto.ResetPasswordDto;
import com.optimum.eoms.security.dto.*;
import java.io.IOException;
import java.util.Map;

/** used to declare required methods for login service */
public interface LoginService {
  Map<String, Object> login(LoginRequest loginRequest) throws IOException;

  Map<String, Object> refresh(RefreshRequest refreshRequest);

  String generateQRCode(String username);

  Map<String, Object> validate(ValidationCodeDto validationCodeDto);

  Map<String, Object> getUserDetails(PasswordRequest passwordRequest);

  Map<String, Object> savePassword(Integer userId, PasswordDto passwordDto);

  Map<String, Object> resetPassword(Integer userId, ResetPasswordDto resetPasswordDto);
}
