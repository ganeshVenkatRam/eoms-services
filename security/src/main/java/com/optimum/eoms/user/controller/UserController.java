package com.optimum.eoms.user.controller;

import static com.optimum.eoms.common.enums.ExceptionType.RECORD_CONFLICT_EXCEPTION;

import com.optimum.eoms.common.constants.AppConstants;
import com.optimum.eoms.common.exception.ConflictException;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.model.user.dto.ResetPasswordDto;
import com.optimum.eoms.model.user.dto.UserDto;
import com.optimum.eoms.model.user.dto.UserSearchParamDto;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.dto.ForgotPasswordDto;
import com.optimum.eoms.security.service.LoginService;
import com.optimum.eoms.user.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@Slf4j
public class UserController {
  @Autowired UserService userService;
  @Autowired LoginService loginService;

  /**
   * Searches all the User related record
   *
   * @param searchParamDto - of UserSearchParamDto
   * @return ResponseEntity
   */
  @PostMapping("/search")
  public ResponseEntity<Object> search(@RequestBody UserSearchParamDto searchParamDto) {
    log.info("into search {}", searchParamDto);
    UserInfoDto userInfo =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    return ResponseEntity.ok(userService.search(userInfo, searchParamDto));
  }

  /**
   * Create the record in User
   *
   * @param dto of User
   * @return ResponseEntity
   */
  @PostMapping("")
  public ResponseEntity<Object> createUser(@Valid @RequestBody UserDto dto) {
    log.info("into create {}", dto);
    UserInfoDto userInfo =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    return new ResponseEntity<>(userService.createUser(userInfo, dto), HttpStatus.CREATED);
  }

  /**
   * Update the record in User
   *
   * @param dto of User
   * @return ResponseEntity
   */
  @PutMapping("/{userId}")
  public ResponseEntity<Object> updateUser(
      @PathVariable("userId") Integer userId, @Valid @RequestBody UserDto dto) {
    log.info("into update {}", dto);
    if (!userId.equals(dto.getUserId())) {
      throw new ConflictException(AppConstants.RECORD_CONFLICT, RECORD_CONFLICT_EXCEPTION);
    }
    UserInfoDto userInfo =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    return new ResponseEntity<>(userService.updateUser(userInfo, dto), HttpStatus.CREATED);
  }

  /**
   * Retrieve the record in User
   *
   * @param userId - id of User
   * @return ResponseEntity
   */
  @GetMapping("/{userId}")
  public ResponseEntity<Object> getUser(@PathVariable("userId") Integer userId) {
    log.info("into get {}", userId);
    UserInfoDto userInfo =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    return ResponseEntity.ok(userService.getUser(userInfo, userId));
  }

  /**
   * activate/deactivate the record in User
   *
   * @param userId
   * @return ResponseEntity
   */
  @PatchMapping("/{userId}/{version}")
  public ResponseEntity<Object> toggleStatusUser(
      @PathVariable("userId") Integer userId, @PathVariable("version") Integer version) {
    log.info("into toggleStatus {}", userId);
    UserInfoDto userInfo =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    userService.toggleStatusUser(userInfo, userId, version);
    return new ResponseEntity<>(HttpStatus.OK);
  }

  /**
   * used to get the user details of currently logged user from the given jwt access token
   *
   * @return userInfoDto
   */
  @GetMapping("/info")
  public ResponseEntity<Object> getUserInfo() {
    log.info("into getUserInfo() ");
    UserInfoDto userInfoDto =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    return ResponseEntity.ok(userInfoDto);
  }

  @GetMapping("/invite/{userId}/{username}")
  public ResponseEntity<Object> getInvite(
      @PathVariable Integer userId, @PathVariable String username) {
    UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
    String hashKey = null;
    String inviteUrl = userService.getInvite(userSecurityDetailsDto, hashKey);
    if (inviteUrl != null) {
      return ResponseEntity.ok(inviteUrl);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  @GetMapping("/invite/resend/{userId}")
  public ResponseEntity<Object> resendInvite(@PathVariable Integer userId) {
    log.info("into resendInvite() ");
    UserInfoDto userInfoDto =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    userService.addEmailToQueue(userInfoDto, userId);
    return new ResponseEntity<>(HttpStatus.OK);
  }

  @PostMapping("/forgotpassword")
  public ResponseEntity<Object> forgotPassword(@RequestBody ForgotPasswordDto dto) {
    log.info("into forgotPassword() ");
    userService.addForgotPaswordEmailToQueue(dto);
    return new ResponseEntity<>(HttpStatus.OK);
  }

  @PostMapping("/forgotpassword/{userId}")
  public ResponseEntity<Object> forgotPassword(
      HttpServletRequest request, @PathVariable Integer userId, @RequestBody ResetPasswordDto dto) {
    log.info("into forgotpassword() ");
    String passwordToken = request.getHeader(SecurityConstants.AUTHORIZATION);
    UserInfoDto userInfoDto =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();

    Map<String, Object> userDetailsMap =
        userService.forgotPassword(userInfoDto, userId, dto, passwordToken);
    if (!userDetailsMap.isEmpty()) {
      if (userDetailsMap.containsKey(SecurityConstants.ERROR_MESSAGE_LIST)) {
        return new ResponseEntity<>(
            userDetailsMap.get(SecurityConstants.ERROR_MESSAGE_LIST), HttpStatus.CONFLICT);
      }
      return ResponseEntity.ok(userDetailsMap);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  @PostMapping("/changepassword/{userId}")
  public ResponseEntity<Object> changepassword(
      HttpServletRequest request, @PathVariable Integer userId, @RequestBody ResetPasswordDto dto) {
    log.info("into changepassword() ");
    String accessToken = request.getHeader(SecurityConstants.AUTHORIZATION);
    UserInfoDto userInfoDto =
        (UserInfoDto) SecurityContextHolder.getContext().getAuthentication().getDetails();
    Map<String, Object> userDetailsMap =
        userService.changePassword(userInfoDto, userId, dto, accessToken);
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
