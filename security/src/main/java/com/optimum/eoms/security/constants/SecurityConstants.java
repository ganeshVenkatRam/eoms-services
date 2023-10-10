package com.optimum.eoms.security.constants;

public class SecurityConstants {
  public enum TokenType {
    BEARER
  }

  public static final String AUTHORIZATION = "Authorization";

  public static final String BEARER_TOKEN = "Bearer";

  public static final String ISSUE_DATE = "issueDate";

  public static final String EXPIRED_DATE = "expiredDate";

  public static final String ROLES = "roles";

  public static final String FUNCTIONS = "functions";

  public static final String HASH = "hash";

  public static final String USER_NAME = "username";

  public static final String ACCESS_TOKEN = "accessToken";

  public static final String REFRESH_TOKEN = "refreshToken";

  public static final String PASSWORD_TOKEN = "passwordToken";

  public static final String ACCESS_TOKEN_TYPE = "JWT-ACCESS";

  public static final String REFRESH_TOKEN_TYPE = "JWT-REFRESH";

  public static final String PASSWORD_TOKEN_TYPE = "JWT-PASSWORD";

  public static final String USER_INFO_RESULT = "UserInfoResult";

  public static final String USER_ID = "userId";

  public static final String OPTIMUM_EMAIL_ADDRESS = "optimumEmailAddress";

  public static final String USER_INFO_CACHE = "userInfoCache";

  public static final String MFA_ENABLED = "mfaEnabled";

  public static final String MFA_REGISTERED = "mfaRegistered";

  public static final String PASSWORD_CREATED = "passwordCreated";

  public static final String IS_RELOGIN_REQUIRED = "isReloginRequired";

  public static final String IS_VALID_AUTH_CODE = "isValidAuthCode";

  public static final String UNAUTHORIZED_USER_NOT_FOUND = "user not found";

  public static final String SECRET_KEY_NOT_FOUND = "secret key not found";

  public static final String ERROR_MESSAGE_LIST = "errorMessageList";

  public static final String CONFLICT_PASSWORD_CONFIRM_PASSWORD_NULL =
      "password and confirm password should not be null";
  public static final String CONFLICT_PASSWORD_CONFIRM_PASSWORD_MATCH =
      "password and confirm password should be same";
  public static final String CONFLICT_OLD_PASSWORD_MISMATCH = "the old password is incorrect";
}
