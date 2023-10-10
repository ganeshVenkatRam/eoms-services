package com.optimum.eoms.security.controller;

import com.optimum.eoms.model.user.dto.ResetPasswordDto;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.dto.*;
import com.optimum.eoms.security.service.LoginService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** used to provide login related APIs */
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class LoginController {
  @Autowired LoginService loginService;

  /**
   * used to log in with user credentials
   *
   * @param loginRequest login credentials - username and password
   * @return responseEntity
   */
  @PostMapping("/login")
  public ResponseEntity<Map<String, Object>> login(@RequestBody @Valid LoginRequest loginRequest)
      throws IOException {
    log.info("into login()");
    Map<String, Object> tokenMap = loginService.login(loginRequest);
    if (!tokenMap.isEmpty()) {
      return ResponseEntity.ok(tokenMap);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  /**
   * used to get both access token and refresh token
   *
   * @param refreshRequest refresh token
   * @return responseEntity
   */
  @PostMapping("/refresh")
  public ResponseEntity<Map<String, Object>> refresh(
      @RequestBody @Valid RefreshRequest refreshRequest) {
    log.info("into refresh()");
    Map<String, Object> tokenMap = loginService.refresh(refreshRequest);
    if (!tokenMap.isEmpty()) {
      return ResponseEntity.ok(tokenMap);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  @GetMapping("/generate/{username}")
  public ResponseEntity<Object> generateQRCode(@PathVariable String username) {
    return ResponseEntity.ok(loginService.generateQRCode(username));
  }

  @PostMapping("/validate/authcode")
  public ResponseEntity<Object> validate(@RequestBody ValidationCodeDto validationCodeDto) {
    return ResponseEntity.ok(loginService.validate(validationCodeDto));
  }

  @PostMapping("/set-password")
  public ResponseEntity<Object> getUserDetails(@RequestBody PasswordRequest passwordRequest) {
    Map<String, Object> userDetailsMap = loginService.getUserDetails(passwordRequest);
    if (!userDetailsMap.isEmpty()) {
      return ResponseEntity.ok(userDetailsMap);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  @PostMapping("/set-password/{userId}")
  public ResponseEntity<Object> savePassword(
      @PathVariable Integer userId, @RequestBody @Valid PasswordDto passwordDto) {
    Map<String, Object> userDetailsMap = loginService.savePassword(userId, passwordDto);
    if (!userDetailsMap.isEmpty()) {
      if (userDetailsMap.containsKey(SecurityConstants.ERROR_MESSAGE_LIST)) {
        return new ResponseEntity<>(
            userDetailsMap.get(SecurityConstants.ERROR_MESSAGE_LIST), HttpStatus.CONFLICT);
      }
      return ResponseEntity.ok(userDetailsMap);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  @PostMapping("/reset-password/{username}/{userId}")
  public ResponseEntity<Object> resetPassword(
          @PathVariable String username, @PathVariable Integer userId, @RequestBody ResetPasswordDto resetPasswordDto) {
    Map<String, Object> userDetailsMap = loginService.resetPassword(userId, resetPasswordDto);
    if (!userDetailsMap.isEmpty()) {
      if (userDetailsMap.containsKey(SecurityConstants.ERROR_MESSAGE_LIST)) {
        return new ResponseEntity<>(
                userDetailsMap.get(SecurityConstants.ERROR_MESSAGE_LIST), HttpStatus.CONFLICT);
      }
      return ResponseEntity.ok(userDetailsMap);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }
}
