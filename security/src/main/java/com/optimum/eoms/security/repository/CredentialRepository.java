package com.optimum.eoms.security.repository;

import static com.optimum.eoms.common.enums.ExceptionType.UNAUTHORIZED_EXCEPTION;

import com.optimum.eoms.common.exception.UnAuthorizedRequestException;
import com.optimum.eoms.model.user.entity.User;
import com.optimum.eoms.model.user.repository.UserRepository;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.warrenstrange.googleauth.ICredentialRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CredentialRepository implements ICredentialRepository {

  @Autowired UserRepository userRepository;

  @Override
  public String getSecretKey(String username) {
    Optional<User> user = userRepository.findByUsernameAndActiveTrue(username);
    if (user.isPresent()) {
      if (user.get().getSecretKey() != null) {
        return user.get().getSecretKey();
      } else {
        throw new UnAuthorizedRequestException(
            SecurityConstants.SECRET_KEY_NOT_FOUND, UNAUTHORIZED_EXCEPTION);
      }
    } else {
      throw new UnAuthorizedRequestException(
          SecurityConstants.UNAUTHORIZED_USER_NOT_FOUND, UNAUTHORIZED_EXCEPTION);
    }
  }

  @Override
  public void saveUserCredentials(
      String username, String secretKey, int validationCode, List<Integer> scratchCodes) {
    Optional<User> user = userRepository.findByUsernameAndActiveTrue(username);
    if (user.isPresent()) {
      User userExists = user.get();
      userExists.setSecretKey(secretKey);
      userRepository.save(userExists);
    }
  }
}
