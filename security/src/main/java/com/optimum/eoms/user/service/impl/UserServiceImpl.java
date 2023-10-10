package com.optimum.eoms.user.service.impl;

import static com.optimum.eoms.common.enums.ExceptionType.*;

import com.optimum.eoms.common.constants.AppConstants;
import com.optimum.eoms.common.enums.ExceptionType;
import com.optimum.eoms.common.exception.ConflictException;
import com.optimum.eoms.common.exception.RecordAlreadyExistsException;
import com.optimum.eoms.common.exception.RecordNotFoundException;
import com.optimum.eoms.email.service.EmailQueueService;
import com.optimum.eoms.model.common.dto.SearchResponseDto;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.model.common.repository.CommonRepository;
import com.optimum.eoms.model.email.constants.EmailConstants;
import com.optimum.eoms.model.email.dto.EmailDto;
import com.optimum.eoms.model.employee.entity.EmployeeOnboarding;
import com.optimum.eoms.model.employee.entity.EmployeePersonalInfo;
import com.optimum.eoms.model.employee.repository.EmployeeOnboardingRepository;
import com.optimum.eoms.model.employee.repository.EmployeePersonalInfoRepository;
import com.optimum.eoms.model.user.dto.ResetPasswordDto;
import com.optimum.eoms.model.user.dto.UserDto;
import com.optimum.eoms.model.user.dto.UserSearchParamDto;
import com.optimum.eoms.model.user.dto.UserSearchResultsDto;
import com.optimum.eoms.model.user.entity.User;
import com.optimum.eoms.model.user.repository.UserRepository;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.dto.ForgotPasswordDto;
import com.optimum.eoms.security.dto.PasswordDto;
import com.optimum.eoms.security.entity.UserToken;
import com.optimum.eoms.security.repository.UserTokenRepository;
import com.optimum.eoms.security.service.JwtService;
import com.optimum.eoms.security.service.RedisService;
import com.optimum.eoms.security.service.impl.AuthenticationTokenImpl;
import com.optimum.eoms.security.service.impl.LoginServiceImpl;
import com.optimum.eoms.security.util.SessionUser;
import com.optimum.eoms.user.repository.UserSearchRepository;
import com.optimum.eoms.user.service.UserService;
import io.jsonwebtoken.Claims;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@Slf4j
public class UserServiceImpl implements UserService {

  @Autowired EmailQueueService emailQueueService;

  @Autowired JwtService jwtService;

  @Autowired UserRepository userRepository;

  @Autowired UserSearchRepository userSearchRepository;
  @Autowired EmployeeOnboardingRepository employeeOnboardingRepository;

  @Autowired EmployeePersonalInfoRepository employeePersonalInfoRepository;
  @Autowired CommonRepository commonRepository;
  @Autowired ModelMapper modelMapper;
  @Autowired LoginServiceImpl loginService;
  @Autowired UserTokenRepository userTokenRepository;
  @Autowired RedisService redisService;

  @Value("${ui.setPassword.url}")
  private String setPasswordUrl;

  @Value("${ui.setForgotPassword.url}")
  private String setForgotPasswordUrl;
  /**
   * Searches User related records
   *
   * @param userInfo of UserInfoDto
   * @param searchParamDto of UserSearchParamDto
   * @return SearchResponseDto consist of List<UserSearchResultsDto>
   */
  @Override
  public SearchResponseDto search(UserInfoDto userInfo, UserSearchParamDto searchParamDto) {
    log.info("Search User params {} ", searchParamDto);
    SearchResponseDto searchResponseDto = new SearchResponseDto();
    List<UserSearchResultsDto> data = userSearchRepository.search(userInfo, searchParamDto);
    if (data != null && !data.isEmpty()) {
      searchResponseDto.setTotalRecords(data.get(0).getTotalRecords());
      searchResponseDto.setData(data);
    }
    return searchResponseDto;
  }

  /**
   * Create the record of User Throw exception if already exist with same key
   *
   * @param dto - Type of User
   * @return UserDto
   */
  @Override
  public UserDto createUser(UserInfoDto userInfo, UserDto dto) {
    log.info("saveUser  {}", dto);
    try {
      dto.setCompanyId(userInfo.getCompanyId());
      UserDto createdDto =
          modelMapper.map(userRepository.save(modelMapper.map(dto, User.class)), UserDto.class);

      // set createdByName and updatedByName
      createdDto.setCreatedByName(
          commonRepository.getEmpCodeAndFullName(createdDto.getCreatedBy()));
      if (createdDto.getUpdatedBy() != null) {
        createdDto.setUpdatedByName(
            commonRepository.getEmpCodeAndFullName(createdDto.getUpdatedBy()));
      }
      addEmailToQueue(userInfo, createdDto.getUserId());
      return createdDto;
    } catch (DataAccessException dataAccessException) {
      throw new RecordAlreadyExistsException(
          AppConstants.RECORD_ALREADY_EXISTS, ExceptionType.RECORD_ALREADY_EXISTS_EXCEPTION);
    }
  }

  public void addEmailToQueue(UserInfoDto userInfo, Integer userId) {
    EmailDto emailDto = new EmailDto();
    emailDto.setEmailType(EmailConstants.EMAIL_TEMPLATE_USER_CREATION);
    Optional<EmployeePersonalInfo> employeePersonalInfo =
        employeePersonalInfoRepository.findByEmpId(userId);
    if (!employeePersonalInfo.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }
    emailDto.setEmailToAddress(
        Arrays.asList(
            employeePersonalInfo.get().getOptimumEmailAddress(),
            employeePersonalInfo.get().getPersonalEmailAddress()));
    Optional<EmployeeOnboarding> employeeOnboarding =
        employeeOnboardingRepository.findByEmpId(userId);
    if (!employeeOnboarding.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }
    Map<String, String> emailMap = new HashMap<>();
    emailMap.put(EmailConstants.EMAIL_CONTENT_USER_NAME, employeeOnboarding.get().getEmpCode());
    emailMap.put(EmailConstants.EMAIL_CONTENT_FULL_NAME, employeeOnboarding.get().getFullName());

    UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
    userSecurityDetailsDto.setUserId(userId);
    userSecurityDetailsDto.setUsername(employeeOnboarding.get().getEmpCode());

    SessionUser sessionUser = new SessionUser();
    sessionUser.setUsername(userSecurityDetailsDto.getUsername());
    sessionUser.setCreated(new Date());
    AuthenticationTokenImpl auth =
        new AuthenticationTokenImpl(
            userSecurityDetailsDto.getUsername(), userSecurityDetailsDto.getAuthorities());
    auth.setAuthenticated(true);
    auth.setDetails(sessionUser);
    String hashKey = auth.getHash();

    emailMap.put(
        EmailConstants.EMAIL_CONTENT_APPLICATION_URL, getInvite(userSecurityDetailsDto, hashKey));
    emailDto.setEmailMap(emailMap);
    emailQueueService.addEmailToQueue(userInfo, emailDto);
  }

  @Override
  public void addForgotPaswordEmailToQueue(ForgotPasswordDto dto) {
    EmailDto emailDto = new EmailDto();
    emailDto.setEmailType(EmailConstants.EMAIL_TEMPLATE_USER_FORGOT_PASSWORD);
    Optional<User> optUser = userRepository.findByUsernameAndActiveTrue(dto.getUsername());

    if (!optUser.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }

    User user = optUser.get();
    Optional<EmployeePersonalInfo> employeePersonalInfo =
        employeePersonalInfoRepository.findByEmpIdAndDob(
            user.getUserId(), new java.sql.Date(dto.getDob().getTime()));

    if (!employeePersonalInfo.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }

    emailDto.setEmailToAddress(
        Arrays.asList(
            employeePersonalInfo.get().getOptimumEmailAddress(),
            employeePersonalInfo.get().getPersonalEmailAddress()));
    Optional<EmployeeOnboarding> employeeOnboarding =
        employeeOnboardingRepository.findByEmpId(user.getUserId());

    if (!employeeOnboarding.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }

    // reset password to null
    user.setPassword(null);
    userRepository.save(user);

    Map<String, String> emailMap = new HashMap<>();
    emailMap.put(EmailConstants.EMAIL_CONTENT_USER_NAME, employeeOnboarding.get().getEmpCode());
    emailMap.put(EmailConstants.EMAIL_CONTENT_FULL_NAME, employeeOnboarding.get().getFullName());

    UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
    userSecurityDetailsDto.setUserId(optUser.get().getUserId());
    userSecurityDetailsDto.setUsername(dto.getUsername());

    SessionUser sessionUser = new SessionUser();
    sessionUser.setUsername(userSecurityDetailsDto.getUsername());
    sessionUser.setCreated(new Date());
    AuthenticationTokenImpl auth =
        new AuthenticationTokenImpl(
            userSecurityDetailsDto.getUsername(), userSecurityDetailsDto.getAuthorities());
    auth.setAuthenticated(true);
    auth.setDetails(sessionUser);
    String hashKey = auth.getHash();

    emailMap.put(
        EmailConstants.EMAIL_CONTENT_APPLICATION_URL,
        getForgotPasswordInvite(userSecurityDetailsDto, hashKey));
    emailDto.setEmailMap(emailMap);
    UserInfoDto userInfoDto = new UserInfoDto();
    userInfoDto.setUserId(user.getUserId());
    userInfoDto.setCompanyId(user.getCompanyId());
    emailQueueService.addEmailToQueue(userInfoDto, emailDto);
  }

  @Override
  public Map<String, Object> changePassword(
      UserInfoDto userInfoDto,
      Integer userId,
      ResetPasswordDto resetPasswordDto,
      String accessToken) {
    Optional<User> user = userRepository.findByUserId(userId);
    if (!user.isPresent()) {
      throw new RecordNotFoundException(AppConstants.RECORD_DID_NOT_FIND, RECORD_NOT_FOUND);
    }
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    PasswordDto passwordDto = new PasswordDto();
    Map<String, Object> savePasswordMap;
    if (passwordEncoder.matches(resetPasswordDto.getOldPassword(), user.get().getPassword())) {
      passwordDto.setPassword(resetPasswordDto.getPassword());
      passwordDto.setConfirmPassword(resetPasswordDto.getConfirmPassword());
      savePasswordMap = loginService.savePassword(userId, passwordDto);
      UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
      userSecurityDetailsDto.setUserId(userId);
      userSecurityDetailsDto.setUsername(userInfoDto.getUsername());
      if (StringUtils.isNotEmpty(accessToken)) {
        accessToken = accessToken.split(SecurityConstants.BEARER_TOKEN)[1].trim();
      }
      Optional<UserToken> userToken = userTokenRepository.findByAccessToken(accessToken);
      if (userToken.isPresent()) {
        UserToken userTokenUpdate = userToken.get();
        userTokenUpdate.setExpired(true);
        UserToken accessTokenUpdate = userTokenRepository.save(userTokenUpdate);
        Claims claims = jwtService.getClaims(userTokenUpdate.getAccessToken());
        if (claims != null && claims.get(SecurityConstants.USER_NAME) != null) {
          String username = claims.get(SecurityConstants.USER_NAME).toString();
          String hashKeyClaim = claims.get(SecurityConstants.HASH).toString();
          if (accessTokenUpdate != null) {
            redisService.removeHashValue(
                String.format("%s:%s", username.toLowerCase(), hashKeyClaim), hashKeyClaim);
          }
        }
      }
    } else {
      log.error("the old password is incorrect");
      throw new ConflictException(
          SecurityConstants.CONFLICT_OLD_PASSWORD_MISMATCH, RECORD_CONFLICT_EXCEPTION);
    }
    return savePasswordMap;
  }

  @Override
  public Map<String, Object> forgotPassword(
      UserInfoDto userInfoDto,
      Integer userId,
      ResetPasswordDto resetPasswordDto,
      String passwordToken) {
    PasswordDto passwordDto = new PasswordDto();
    Map<String, Object> savePasswordMap;
    passwordDto.setPassword(resetPasswordDto.getPassword());
    passwordDto.setConfirmPassword(resetPasswordDto.getConfirmPassword());
    savePasswordMap = loginService.savePassword(userId, passwordDto);

    UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
    userSecurityDetailsDto.setUserId(userId);
    userSecurityDetailsDto.setUsername(userInfoDto.getUsername());
    if (StringUtils.isNotEmpty(passwordToken)) {
      passwordToken = passwordToken.split(SecurityConstants.BEARER_TOKEN)[1].trim();
    }
    Optional<UserToken> userToken = userTokenRepository.findByAccessToken(passwordToken);
    if (userToken.isPresent()) {
      UserToken userTokenUpdate = userToken.get();
      userTokenUpdate.setExpired(true);
      UserToken accessTokenUpdate = userTokenRepository.save(userTokenUpdate);
      Claims claims = jwtService.getClaims(userTokenUpdate.getAccessToken());
      if (claims != null && claims.get(SecurityConstants.USER_NAME) != null) {
        String username = claims.get(SecurityConstants.USER_NAME).toString();
        String hashKeyClaim = claims.get(SecurityConstants.HASH).toString();
        if (accessTokenUpdate != null) {
          redisService.removeHashValue(
              String.format("%s:%s", username.toLowerCase(), hashKeyClaim), hashKeyClaim);
        }
      }
    }
    return savePasswordMap;
  }

  /**
   * Updates the record in User throw error if already exist
   *
   * @param dto - Type of User
   * @return UserDto
   */
  @Override
  public UserDto updateUser(UserInfoDto userInfo, UserDto dto) {
    log.info("updateUser  {}", dto);

    Optional<User> data = userRepository.findByUserId(dto.getUserId());
    if (!data.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }
    try {
      User dbRecord = data.get();

      if (!dbRecord.getActive()) { // invalid update
        throw new ConflictException(AppConstants.RECORD_INACTIVE, RECORD_INACTIVE_EXCEPTION);
      }
      if (dbRecord.getVersion() != dto.getVersion()) {
        throw new ConflictException(AppConstants.RECORD_CONFLICT, RECORD_CONFLICT_EXCEPTION);
      }
      dto.setPassword(dbRecord.getPassword());
      modelMapper.map(dto, dbRecord);
      dbRecord.setVersion(dbRecord.getVersion() + 1);

      // use saveAndFlush() to catch unique constraints
      UserDto updatedDto = modelMapper.map(userRepository.saveAndFlush(dbRecord), UserDto.class);

      // set createdByName and updatedByName
      updatedDto.setCreatedByName(
          commonRepository.getEmpCodeAndFullName(updatedDto.getCreatedBy()));
      if (updatedDto.getUpdatedBy() != null) {
        updatedDto.setUpdatedByName(
            commonRepository.getEmpCodeAndFullName(updatedDto.getUpdatedBy()));
      }
      return updatedDto;

    } catch (DataIntegrityViolationException dataIntegrityViolationException) {
      throw new RecordAlreadyExistsException(
          AppConstants.RECORD_ALREADY_EXISTS, ExceptionType.RECORD_ALREADY_EXISTS_EXCEPTION);
    }
  }

  /**
   * Retrieves the record for User throw error if record does not exist
   *
   * @param userId
   * @return UserDto
   */
  @Override
  public UserDto getUser(UserInfoDto userInfo, Integer userId) {
    log.info("getUser {}", userId);

    Optional<User> data = userRepository.findByUserId(userId);
    if (!data.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }

    User dbRecord = data.get();
    UserDto dto = modelMapper.map(dbRecord, UserDto.class);
    Optional<EmployeeOnboarding> employeeOnboarding =
        employeeOnboardingRepository.findByEmpId(userId);
    if (employeeOnboarding.isPresent()) {
      dto.setFullName(employeeOnboarding.get().getFullName());
    }
    // append created by name and updated by name
    dto.setCreatedByName(commonRepository.getEmpCodeAndFullName(dbRecord.getCreatedBy()));
    if (dbRecord.getUpdatedBy() != null) {
      dto.setUpdatedByName(commonRepository.getEmpCodeAndFullName(dbRecord.getUpdatedBy()));
    }
    return dto;
  }

  /**
   * Activates/deactivate the record. throw exception if record does not exist
   *
   * @param userId
   * @return void
   */
  @Override
  public void toggleStatusUser(UserInfoDto userInfo, Integer userId, Integer version) {
    log.info("toggleStatus {}", userId);

    Optional<User> data = userRepository.findByUserId(userId);
    if (!data.isPresent()) {
      throw new RecordNotFoundException(
          AppConstants.RECORD_DID_NOT_FIND, ExceptionType.RECORD_NOT_FOUND);
    }
    User dbRecord = data.get();
    if (dbRecord.getVersion().intValue() != version.intValue()) {
      throw new ConflictException(AppConstants.RECORD_CONFLICT, RECORD_CONFLICT_EXCEPTION);
    }
    dbRecord.setActive(!dbRecord.getActive()); // toggle the flag
    dbRecord.setVersion(dbRecord.getVersion() + 1);
    userRepository.save(dbRecord);
  }

  @Override
  public String getInvite(UserSecurityDetailsDto userSecurityDetailsDto, String hashKey) {
    if (userSecurityDetailsDto != null && hashKey != null) {
      try {
        return new URL(setPasswordUrl)
            + "?token="
            + jwtService.generatePasswordToken(userSecurityDetailsDto, hashKey);
      } catch (MalformedURLException e) {
        throw new RuntimeException(e);
      }
    } else {
      throw new RecordNotFoundException(AppConstants.RECORD_DID_NOT_FIND, RECORD_NOT_FOUND);
    }
  }

  @Override
  public String getForgotPasswordInvite(
      UserSecurityDetailsDto userSecurityDetailsDto, String hashKey) {
    if (userSecurityDetailsDto != null && hashKey != null) {
      try {
        return new URL(setForgotPasswordUrl)
            + "?token="
            + jwtService.generatePasswordToken(userSecurityDetailsDto, hashKey);
      } catch (MalformedURLException e) {
        throw new RuntimeException(e);
      }
    } else {
      throw new RecordNotFoundException(AppConstants.RECORD_DID_NOT_FIND, RECORD_NOT_FOUND);
    }
  }
}
