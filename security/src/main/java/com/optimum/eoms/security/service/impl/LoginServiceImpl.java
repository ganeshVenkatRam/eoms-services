package com.optimum.eoms.security.service.impl;

import static com.optimum.eoms.common.enums.ExceptionType.RECORD_CONFLICT_EXCEPTION;
import static com.optimum.eoms.common.enums.ExceptionType.RECORD_NOT_FOUND;

import com.optimum.eoms.common.constants.AppConstants;
import com.optimum.eoms.common.enums.ExceptionType;
import com.optimum.eoms.common.exception.ConflictException;
import com.optimum.eoms.common.exception.RecordAlreadyExistsException;
import com.optimum.eoms.common.exception.RecordNotFoundException;
import com.optimum.eoms.common.util.AppUtil;
import com.optimum.eoms.model.appconfig.constants.AppConfigConstants;
import com.optimum.eoms.model.appconfig.entity.AppConfig;
import com.optimum.eoms.model.appconfig.repository.AppConfigRepository;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.model.user.constants.UserConstants;
import com.optimum.eoms.model.user.dto.ResetPasswordDto;
import com.optimum.eoms.model.user.dto.UserPasswordHistoryDto;
import com.optimum.eoms.model.user.entity.User;
import com.optimum.eoms.model.user.entity.UserPasswordHistory;
import com.optimum.eoms.model.user.repository.UserPasswordHistoryRepository;
import com.optimum.eoms.model.user.repository.UserRepository;
import com.optimum.eoms.security.configuration.PasswordEncoderConfiguration;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.dto.*;
import com.optimum.eoms.security.entity.UserToken;
import com.optimum.eoms.security.repository.UserTokenRepository;
import com.optimum.eoms.security.service.JwtService;
import com.optimum.eoms.security.service.LoginService;
import com.optimum.eoms.security.service.RedisService;
import com.optimum.eoms.security.util.SessionUser;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import io.jsonwebtoken.Claims;
import io.micrometer.common.util.StringUtils;
import jakarta.transaction.Transactional;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.modelmapper.ModelMapper;
import org.passay.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/** used to provide implementations for login service methods */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class LoginServiceImpl extends LoginBaseServiceImpl implements LoginService {
  @Autowired RedisService redisService;

  @Autowired UserTokenRepository userTokenRepository;

  @Autowired AuthenticationManager authenticationManager;

  @Autowired ModelMapper modelMapper;

  @Autowired JwtService jwtService;

  @Autowired UserRepository userRepository;

  @Autowired GoogleAuthenticator gAuth;

  @Autowired PasswordEncoderConfiguration passwordEncoderConfiguration;

  @Autowired AppConfigRepository appConfigRepository;
  @Autowired UserPasswordHistoryRepository userPwdRepository;

  @Value("${ui.setPassword.url}")
  private String setPasswordUrl;

  /**
   * used to log in with user credentials
   *
   * @param loginRequest request
   * @return loginResponse
   */
  @Override
  public Map<String, Object> login(LoginRequest loginRequest) {
    log.info("into login() ");
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.username(), loginRequest.password()));
    UserSecurityDetailsDto userSecurityDetailsDto =
        (UserSecurityDetailsDto) authentication.getPrincipal();

    return getLoginResponse(userSecurityDetailsDto, true);
  }

  @Override
  public Map<String, Object> refresh(RefreshRequest refreshRequest) {
    log.info("into refresh() ");
    Map<String, Object> tokenMap = new HashMap<>();
    String refreshToken = refreshRequest.refreshToken();
    if (refreshToken != null) {
      Base64.Decoder decoder = Base64.getUrlDecoder();
      String jsonString = new String(decoder.decode((refreshToken.split("\\.")[0])));
      if (StringUtils.isNotEmpty(jsonString)) {
        JSONObject jsonObject = new JSONObject(jsonString);
        if (jsonObject.get("typ").toString().equals(SecurityConstants.REFRESH_TOKEN_TYPE)) {
          Claims claims = jwtService.getClaims(refreshToken);
          if (claims != null && claims.get(SecurityConstants.USER_NAME) != null) {
            String username = claims.get(SecurityConstants.USER_NAME).toString();
            int userId = Integer.parseInt(claims.get(SecurityConstants.USER_ID).toString());
            String hashKeyClaim = claims.get(SecurityConstants.HASH).toString();
            UserInfoDto userInfoDto = getUserInfoDto(userId);
            Optional<User> user = userRepository.findByUserId(userId);
            if (user.isPresent()) {
              userInfoDto.setLastLoginDate(user.get().getLastLoginDate());
            }
            UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
            userSecurityDetailsDto.setUsername(username);
            userSecurityDetailsDto.setUserId(userId);
            userSecurityDetailsDto.setRoleDtoList(userInfoDto.getRoleDtoList());
            redisService.removeHashValue(
                String.format("%s:%s", username.toLowerCase(), hashKeyClaim), hashKeyClaim);
            return getToken(userSecurityDetailsDto, userInfoDto, tokenMap);
          }
        }
      }
    }
    return new HashMap<>();
  }

  public Map<String, Object> getToken(
      UserSecurityDetailsDto userSecurityDetailsDto,
      UserInfoDto userInfoDto,
      Map<String, Object> tokenMap) {
    log.info("into getToken() ");
    SessionUser sessionUser = new SessionUser();
    sessionUser.setUsername(userSecurityDetailsDto.getUsername());
    sessionUser.setCreated(new Date());
    AuthenticationTokenImpl auth =
        new AuthenticationTokenImpl(
            userSecurityDetailsDto.getUsername(), userSecurityDetailsDto.getAuthorities());
    auth.setAuthenticated(true);
    auth.setDetails(sessionUser);
    String hashKey = auth.getHash();

    UserTokenDto accessTokenDto = jwtService.generateAccessToken(userSecurityDetailsDto, hashKey);
    RefreshTokenDto refreshTokenDto =
        jwtService.generateRefreshToken(userSecurityDetailsDto, hashKey);
    if (accessTokenDto.getAccessToken() != null && refreshTokenDto.getRefreshToken() != null) {
      saveUserToken(accessTokenDto);
      if (userInfoDto.getUsername() != null) {
        redisService.setHashValue(
            String.format("%s:%s", userInfoDto.getUsername().toLowerCase(), hashKey),
            hashKey,
            userInfoDto,
            TimeUnit.SECONDS,
            3600L,
            true);
      }
      tokenMap.put(SecurityConstants.ACCESS_TOKEN, accessTokenDto.getAccessToken());
      tokenMap.put(SecurityConstants.REFRESH_TOKEN, refreshTokenDto.getRefreshToken());
    }
    return tokenMap;
  }
  /**
   * used to get login response for the user
   *
   * @param userSecurityDetailsDto security details param
   * @return login response
   */
  public Map<String, Object> getLoginResponse(
      UserSecurityDetailsDto userSecurityDetailsDto, boolean isStepOneAuth) {
    log.info("into getLoginResponse() ");
    Map<String, Object> tokenMap = new HashMap<>();
    UserInfoDto userInfoDto = getUserInfoDto(userSecurityDetailsDto.getUserId());
    userSecurityDetailsDto.setRoleDtoList(userInfoDto.getRoleDtoList());
    Optional<User> user = userRepository.findByUserId(userSecurityDetailsDto.getUserId());
    Timestamp timestamp = new Timestamp(new Date().getTime());
    userInfoDto.setLastLoginDate(timestamp);
    if (user.isPresent()) {
      User userExists = user.get();
      userExists.setLastLoginDate(timestamp);
      userInfoDto.setMfaEnabled(userExists.getMfaEnabled());
      userRepository.save(userExists);
      if (isStepOneAuth && userExists.getMfaEnabled()) {
        // if mfa enabled user logged with valid credentials
        tokenMap.put(SecurityConstants.MFA_ENABLED, true);
        if (userExists.getMfaRegistered()) {
          // if mfa enabled user logged with valid credentials and already registered
          tokenMap.put(SecurityConstants.MFA_REGISTERED, true);
        } else {
          // if mfa enabled user logged with valid credentials but not yet registered
          tokenMap.put(SecurityConstants.MFA_REGISTERED, false);
        }
        return tokenMap;
      } else {
        if (!userExists.getMfaEnabled()) {
          // if admin updates mfa_enabled as false when the user logged with valid credentials
          tokenMap.put(SecurityConstants.MFA_ENABLED, false);
          return getToken(userSecurityDetailsDto, userInfoDto, tokenMap);
        }
        if (userExists.getMfaRegistered()) {
          // if mfa enabled and registered user logged with valid credentials and totp verified for
          // login
          tokenMap.put(SecurityConstants.IS_RELOGIN_REQUIRED, false);
          return getToken(userSecurityDetailsDto, userInfoDto, tokenMap);
        } else {
          // if mfa enabled user logged with valid credentials and totp verified for registration
          tokenMap.put(SecurityConstants.IS_RELOGIN_REQUIRED, true);
          userExists.setMfaRegistered(true);
          userRepository.save(userExists);
          return tokenMap;
        }
      }
    } else {
      throw new RecordNotFoundException(
          SecurityConstants.UNAUTHORIZED_USER_NOT_FOUND, RECORD_NOT_FOUND);
    }
  }

  /**
   * used to save the generated token in token table
   *
   * @param userTokenDto dto
   * @return token
   */
  private UserToken saveUserToken(UserTokenDto userTokenDto) {
    log.info("into saveUserToken()");
    return userTokenRepository.save(modelMapper.map(userTokenDto, UserToken.class));
  }

  @Override
  public String generateQRCode(String username) {
    Optional<User> user = userRepository.findByUsernameAndActiveTrue(username);
    if (user.isPresent()) {
      final GoogleAuthenticatorKey key = gAuth.createCredentials(username);
      String otpAuthURL =
          GoogleAuthenticatorQRGenerator.getOtpAuthURL(UserConstants.APP_NAME, username, key);
      return otpAuthURL;
    } else {
      throw new RecordNotFoundException(
          SecurityConstants.UNAUTHORIZED_USER_NOT_FOUND, RECORD_NOT_FOUND);
    }
  }

  @Override
  public Map<String, Object> validate(ValidationCodeDto validationCodeDto) {
    Optional<User> user =
        userRepository.findByUsernameAndActiveTrue(validationCodeDto.getUsername());
    if (user.isPresent()) {
      UserSecurityDetailsDto userSecurityDetailsDto = new UserSecurityDetailsDto();
      userSecurityDetailsDto.setUsername(user.get().getUsername());
      userSecurityDetailsDto.setUserId(user.get().getUserId());
      // if admin updates mfa_enabled as false when the user logged with valid credentials
      if (!user.get().getMfaEnabled()) {
        return getLoginResponse(userSecurityDetailsDto, false);
      }
      boolean isValidAuthCode =
          gAuth.authorizeUser(validationCodeDto.getUsername(), validationCodeDto.getAuthCode());
      if (isValidAuthCode) {
        Map<String, Object> responseMap = getLoginResponse(userSecurityDetailsDto, false);
        responseMap.put(SecurityConstants.IS_VALID_AUTH_CODE, isValidAuthCode);
        return responseMap;
      } else {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put(SecurityConstants.IS_VALID_AUTH_CODE, isValidAuthCode);
        return responseMap;
      }
    } else {
      throw new RecordNotFoundException(
          SecurityConstants.UNAUTHORIZED_USER_NOT_FOUND, RECORD_NOT_FOUND);
    }
  }

  @Override
  public Map<String, Object> getUserDetails(PasswordRequest passwordRequest) {
    String passwordToken = passwordRequest.passwordToken();
    Map<String, Object> tokenMap = new HashMap<>();
    if (passwordToken != null) {
      Base64.Decoder decoder = Base64.getUrlDecoder();
      String jsonString = new String(decoder.decode((passwordToken.split("\\.")[0])));
      if (StringUtils.isNotEmpty(jsonString)) {
        JSONObject jsonObject = new JSONObject(jsonString);
        if (jsonObject.get("typ").toString().equals(SecurityConstants.PASSWORD_TOKEN_TYPE)) {
          Claims claims = jwtService.getClaims(passwordToken);
          if (claims != null) {
            if (claims.get(SecurityConstants.USER_ID) != null) {
              Integer userId = Integer.parseInt(claims.get(SecurityConstants.USER_ID).toString());
              Optional<User> user = userRepository.findByUserId(userId);
              if (user.isPresent()) {
                tokenMap.put(
                    SecurityConstants.USER_ID,
                    Integer.parseInt(claims.get(SecurityConstants.USER_ID).toString()));
                if (claims.get(SecurityConstants.USER_NAME) != null) {
                  tokenMap.put(
                      SecurityConstants.USER_NAME,
                      claims.get(SecurityConstants.USER_NAME).toString());
                }
                if (claims.get(SecurityConstants.OPTIMUM_EMAIL_ADDRESS) != null) {
                  tokenMap.put(
                      SecurityConstants.OPTIMUM_EMAIL_ADDRESS,
                      claims.get(SecurityConstants.OPTIMUM_EMAIL_ADDRESS).toString());
                }
                User userExists = user.get();
                if (!userExists.getMfaEnabled()) {
                  tokenMap.put(SecurityConstants.MFA_ENABLED, false);
                } else {
                  tokenMap.put(SecurityConstants.MFA_ENABLED, true);
                  if (userExists.getMfaRegistered()) {
                    tokenMap.put(SecurityConstants.MFA_REGISTERED, true);
                  } else {
                    tokenMap.put(SecurityConstants.MFA_REGISTERED, false);
                  }
                }
                if (userExists.getPassword() == null) {
                  tokenMap.put(SecurityConstants.PASSWORD_CREATED, false);
                } else {
                  tokenMap.put(SecurityConstants.PASSWORD_CREATED, true);
                }

              } else {
                throw new RecordNotFoundException(
                    SecurityConstants.UNAUTHORIZED_USER_NOT_FOUND, RECORD_NOT_FOUND);
              }
            }
          }
        }
      }
    }
    return tokenMap;
  }

  public Map<String, Object> savePassword(Integer userId, PasswordDto passwordDto) {
    Map<String, Object> tokenMap = new HashMap<>();
    Optional<User> user = userRepository.findByUserId(userId);
    if (!user.isPresent()) {
      throw new RecordNotFoundException(AppConstants.RECORD_DID_NOT_FIND, RECORD_NOT_FOUND);
    }
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    User userExists = user.get();
    String password = passwordDto.getPassword();
    String confirmPassword = passwordDto.getConfirmPassword();
    if (password != null && confirmPassword != null) {
      if (password.equals(confirmPassword)) {
        List<String> errorMessageList = validatePassword(passwordDto.getPassword());
        if (!errorMessageList.isEmpty()) {
          tokenMap.put(SecurityConstants.ERROR_MESSAGE_LIST, errorMessageList);
          return tokenMap;
        }
        
        if (updatePasswordHistory(userId, password)) {
          userExists.setPassword(passwordEncoder.encode(password));
          userExists.setPasswordChangedDate(new Date());
          Optional<AppConfig> appConfig =
                  appConfigRepository.findByAppKey(AppConfigConstants.KEY_USER_PASSWORD_EXPIRY_DAYS);
          LocalDateTime passwordExpiryDate =
                  AppUtil.convertDatetoLocalDateTime(userExists.getPasswordChangedDate())
                          .plusDays(Long.parseLong(appConfig.get().getDescription()));
          userExists.setPasswordExpiryDate(AppUtil.convertLocalDateTimetoDate(passwordExpiryDate));
          userExists.setPasswordExpired(false);
          userRepository.save(userExists);
          tokenMap.put(SecurityConstants.PASSWORD_CREATED, true);
          tokenMap.put(SecurityConstants.USER_NAME, userExists.getUsername());
          tokenMap.put(SecurityConstants.USER_ID, userExists.getUserId());
          if (!userExists.getMfaEnabled()) {
            tokenMap.put(SecurityConstants.MFA_ENABLED, false);
          } else {
            tokenMap.put(SecurityConstants.MFA_ENABLED, true);
            if (userExists.getMfaRegistered()) {
              tokenMap.put(SecurityConstants.MFA_REGISTERED, true);
            } else {
              tokenMap.put(SecurityConstants.MFA_REGISTERED, false);
            }
          }
        }
        return tokenMap;
      } else {
        log.error("password and confirm password should be same");
        throw new ConflictException(
            SecurityConstants.CONFLICT_PASSWORD_CONFIRM_PASSWORD_MATCH, RECORD_CONFLICT_EXCEPTION);
      }
    } else {
      log.error("password and confirm password should not be null");
      throw new ConflictException(
          SecurityConstants.CONFLICT_PASSWORD_CONFIRM_PASSWORD_NULL, RECORD_CONFLICT_EXCEPTION);
    }
  }

  private boolean updatePasswordHistory(Integer userId, String password) {
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    List<String> passwordLists = userPwdRepository.findPasswordByUserIdAndTrue(userId);
    if (!passwordLists.isEmpty()) {
      for (String bcryptPassword : passwordLists) {
        if (passwordEncoder.matches(password, bcryptPassword)) {
          throw new RecordAlreadyExistsException(
                  UserConstants.PASSWORD_HISTORY_VALIDATION,
                  ExceptionType.RECORD_ALREADY_EXISTS_EXCEPTION);
        }
      }
    }
    UserPasswordHistoryDto userPasswordHistoryDto = new UserPasswordHistoryDto();
    userPasswordHistoryDto.setUserId(userId);
    userPasswordHistoryDto.setCompanyId(1);
    userPasswordHistoryDto.setPassword(passwordEncoder.encode(password));
    if (userPwdRepository.countofUserEntries(userId) >= 3) {
      Integer historyId = userPwdRepository.findOldestRecord(userId);
      Optional<UserPasswordHistory> userPasswordHistory = userPwdRepository.findById(historyId);
      userPasswordHistory.get().setActive(false);
    }
    userPwdRepository.save(modelMapper.map(userPasswordHistoryDto, UserPasswordHistory.class));
    return true;
  }
  @Override
  public Map<String, Object> resetPassword(Integer userId, ResetPasswordDto resetPasswordDto) {
    Optional<User> user = userRepository.findByUserId(userId);
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    PasswordDto passwordDto = new PasswordDto();
    if(passwordEncoder.matches(resetPasswordDto.getOldPassword(), user.get().getPassword())) {
      passwordDto.setPassword(resetPasswordDto.getPassword());
      passwordDto.setConfirmPassword(resetPasswordDto.getConfirmPassword());
      return savePassword(userId, passwordDto);
    }
    else {
      log.error("the old password is incorrect");
      throw new ConflictException(
              SecurityConstants.CONFLICT_OLD_PASSWORD_MISMATCH, RECORD_CONFLICT_EXCEPTION);
    }
  }

  private List<String> validatePassword(String password) {

    List<Rule> ruleList = new ArrayList();
    // Rule 1: Password length should be in between 8 and 16 characters
    ruleList.add(new LengthRule(8, 16));
    // Rule 2: No whitespace allowed
    ruleList.add(new WhitespaceRule());
    // Rule 3.a: At least one Upper-case character
    ruleList.add(new CharacterRule(EnglishCharacterData.UpperCase, 1));
    // Rule 3.b: At least one Lower-case character
    ruleList.add(new CharacterRule(EnglishCharacterData.LowerCase, 1));
    // Rule 3.c: At least one digit
    ruleList.add(new CharacterRule(EnglishCharacterData.Digit, 1));
    // Rule 3.d: At least one special character
    ruleList.add(new CharacterRule(EnglishCharacterData.Special, 1));

    PasswordValidator passwordValidator = new PasswordValidator(ruleList);
    PasswordData passwordData = new PasswordData(password);
    RuleResult ruleResult = passwordValidator.validate(passwordData);

    if (!ruleResult.isValid()) {
      List<String> errorMessageList = passwordValidator.getMessages(ruleResult);
      return errorMessageList;
    } else {
      return new ArrayList<>();
    }
  }
}
