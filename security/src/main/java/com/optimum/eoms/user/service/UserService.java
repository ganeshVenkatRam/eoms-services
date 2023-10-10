package com.optimum.eoms.user.service;

import com.optimum.eoms.model.common.dto.SearchResponseDto;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.model.user.dto.ResetPasswordDto;
import com.optimum.eoms.model.user.dto.UserDto;
import com.optimum.eoms.model.user.dto.UserSearchParamDto;
import com.optimum.eoms.security.dto.ForgotPasswordDto;

import java.util.Map;

public interface UserService {

  SearchResponseDto search(UserInfoDto userInfo, UserSearchParamDto searchParamDto);

  UserDto createUser(UserInfoDto userInfo, UserDto dto);

  UserDto updateUser(UserInfoDto userInfo, UserDto dto);

  UserDto getUser(UserInfoDto userInfo, Integer userId);

  void toggleStatusUser(UserInfoDto userInfo, Integer userId, Integer version);

  String getInvite(UserSecurityDetailsDto userSecurityDetailsDto, String hashKey);

  String getForgotPasswordInvite(UserSecurityDetailsDto userSecurityDetailsDto, String hashKey);

  void addEmailToQueue(UserInfoDto userInfo, Integer userId);

  void addForgotPaswordEmailToQueue(ForgotPasswordDto dto);
  Map<String, Object> changePassword(UserInfoDto dto, Integer userId, ResetPasswordDto resetPasswordDto, String accessToken);
  Map<String, Object> forgotPassword(UserInfoDto dto, Integer userId, ResetPasswordDto resetPasswordDto, String passwordToken);
}
