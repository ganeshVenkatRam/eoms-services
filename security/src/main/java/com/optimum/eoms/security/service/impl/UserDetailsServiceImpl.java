package com.optimum.eoms.security.service.impl;

import com.optimum.eoms.model.appfunction.dto.AppFunctionDto;
import com.optimum.eoms.model.appfunction.entity.AppFunction;
import com.optimum.eoms.model.appfunction.repository.AppFunctionRepository;
import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.model.user.entity.User;
import com.optimum.eoms.model.user.repository.UserRepository;
import com.optimum.eoms.model.userrole.dto.UserRoleDto;
import com.optimum.eoms.model.userrole.entity.UserRole;
import com.optimum.eoms.model.userrole.repository.UserRoleRepository;
import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/** used to provide user credentials validations for user login */
@Service
@Slf4j
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

  @Autowired UserRepository userRepository;

  @Autowired UserRoleRepository roleRepository;

  @Autowired AppFunctionRepository appFunctionRepository;

  /**
   * used to validate the user and get user and role info from DB
   *
   * @param username
   * @return userdetails
   * @throws UsernameNotFoundException
   */
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    log.info("into loadUserByUsername()");
    ModelMapper modelMapper = new ModelMapper();
    Optional<User> user = userRepository.findByUsernameAndActiveTrue(username);
    if (user.isPresent()) {
      List<UserRole> roleList = roleRepository.listRole(user.get().getUserId());
      List<UserRoleDto> roleDtoList =
          roleList.stream().map(role -> modelMapper.map(role, UserRoleDto.class)).toList();
      List<AppFunction> appFunctionList = new ArrayList<>();
      roleDtoList.stream()
          .forEach(
              userRoleDto -> {
                appFunctionList.addAll(
                    appFunctionRepository.listAppFunction(userRoleDto.getRoleId()));
              });
      List<AppFunctionDto> appFunctionDtoList =
          appFunctionList.stream()
              .map(appFunction -> modelMapper.map(appFunction, AppFunctionDto.class))
              .toList();
      UserSecurityDetailsDto userSecurityDetailsDto =
          modelMapper.map(user, UserSecurityDetailsDto.class);
      userSecurityDetailsDto.setRoleDtoList(roleDtoList);
      userSecurityDetailsDto.setAppFunctionDtoList(appFunctionDtoList);
      return userSecurityDetailsDto;
    } else {
      throw new UsernameNotFoundException(username);
    }
  }
}
