package com.optimum.eoms.security.service.impl;

import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.designation.entity.Designation;
import com.optimum.eoms.model.designation.repository.DesignationRepository;
import com.optimum.eoms.model.employee.entity.EmployeeOnboarding;
import com.optimum.eoms.model.employee.repository.EmployeeOnboardingRepository;
import com.optimum.eoms.model.employee.repository.EmployeePersonalInfoRepository;
import com.optimum.eoms.model.empopsgroup.entity.EmployeeOpsGroupMap;
import com.optimum.eoms.model.empopsgroup.repository.EmployeeOpsGroupMapRepository;
import com.optimum.eoms.model.lovdata.constants.LovDataConstants;
import com.optimum.eoms.model.lovdata.entity.LovData;
import com.optimum.eoms.model.lovdata.repository.LovDataRepository;
import com.optimum.eoms.model.lovdomain.constants.LovDomainConstants;
import com.optimum.eoms.model.userrole.dto.UserRoleDto;
import com.optimum.eoms.model.userrole.entity.UserRole;
import com.optimum.eoms.model.userrole.repository.UserRoleRepository;
import java.util.List;
import java.util.Optional;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;

public class LoginBaseServiceImpl {

  @Autowired EmployeeOnboardingRepository employeeOnboardingRepository;

  @Autowired EmployeePersonalInfoRepository employeePersonalInfoRepository;

  @Autowired EmployeeOpsGroupMapRepository employeeOpsGroupMapRepository;

  @Autowired LovDataRepository lovDataRepository;

  @Autowired DesignationRepository designationRepository;

  @Autowired
  UserRoleRepository roleRepository;

  @Autowired ModelMapper modelMapper;

  public UserInfoDto getUserInfoDto(Integer userId) {
    UserInfoDto userInfoDto = new UserInfoDto();
    Optional<EmployeeOnboarding> data = employeeOnboardingRepository.findByEmpId(userId);
    if (data.isPresent()) {
      EmployeeOnboarding employeeOnboarding = data.get();
      userInfoDto.setCompanyId(employeeOnboarding.getCompanyId());
      userInfoDto.setUserId(employeeOnboarding.getEmpId());
      userInfoDto.setUsername(employeeOnboarding.getEmpCode());
      userInfoDto.setFullName(employeeOnboarding.getFullName());
      userInfoDto.setDesignationId(employeeOnboarding.getDesignationId());
      if (employeeOnboarding.getTitleId() != null) {
        Optional<LovData> lovData = lovDataRepository.findByLovId(employeeOnboarding.getTitleId());
        if (lovData.isPresent()) {
          userInfoDto.setTitleName(lovData.get().getLovKey());
        }
      }
      if (employeeOnboarding.getDesignationId() != null) {
        Optional<Designation> designation =
            designationRepository.findByDesignationId(employeeOnboarding.getDesignationId());
        if (designation.isPresent()) {
          userInfoDto.setDesignationName(designation.get().getDesignationName());
        }
      }
      // check whether the logged in employee is home office or not
      if (employeeOnboarding.getEmpGroupId() != null) {
        Optional<LovData> lovData =
            lovDataRepository.findByLovId(employeeOnboarding.getEmpGroupId());
        if (lovData.isPresent()) {
          userInfoDto.setHomeOffice(
              lovData
                  .get()
                  .getLovKey()
                  .equalsIgnoreCase(LovDataConstants.EMPLOYEE_GROUP_HOME_OFFICE));
        }
      }
      // check the logged in employee is part of any HR group
      LovData opsHrGrpLov =
          lovDataRepository.findByDomainKeyAndLovKey(
              employeeOnboarding.getCompanyId(),
              LovDomainConstants.DOMAIN_EMPLOYEE_OPERATIONAL_GROUP_TYPE,
              LovDataConstants.EMPLOYEE_OPERATIONAL_GROUP_TYPE_HR);
      List<EmployeeOpsGroupMap> hrMapList =
          employeeOpsGroupMapRepository.findByCompanyIdAndEmpOpsGroupTypeIdAndEmpId(
              employeeOnboarding.getCompanyId(),
              opsHrGrpLov.getLovId(),
              employeeOnboarding.getEmpId());
      if (!hrMapList.isEmpty()) {
        userInfoDto.setHrGroup(true);
      }
      // check the logged in employee is part of any FIN group
      LovData opsFinGrpLov =
          lovDataRepository.findByDomainKeyAndLovKey(
              employeeOnboarding.getCompanyId(),
              LovDomainConstants.DOMAIN_EMPLOYEE_OPERATIONAL_GROUP_TYPE,
              LovDataConstants.EMPLOYEE_OPERATIONAL_GROUP_TYPE_FINANCE);
      List<EmployeeOpsGroupMap> finMapList =
          employeeOpsGroupMapRepository.findByCompanyIdAndEmpOpsGroupTypeIdAndEmpId(
              employeeOnboarding.getCompanyId(),
              opsFinGrpLov.getLovId(),
              employeeOnboarding.getEmpId());
      if (!finMapList.isEmpty()) {
        userInfoDto.setFinGroup(true);
      }
      LovData opsOfferApproverGrpLov =
          lovDataRepository.findByDomainKeyAndLovKey(
              employeeOnboarding.getCompanyId(),
              LovDomainConstants.DOMAIN_EMPLOYEE_OPERATIONAL_GROUP_TYPE,
              LovDataConstants.EMPLOYEE_OPERATIONAL_GROUP_TYPE_OFFER_APPROVER);
      List<EmployeeOpsGroupMap> offerApproverMapList =
          employeeOpsGroupMapRepository.findByCompanyIdAndEmpOpsGroupTypeIdAndEmpId(
              employeeOnboarding.getCompanyId(),
              opsOfferApproverGrpLov.getLovId(),
              employeeOnboarding.getEmpId());
      if (!offerApproverMapList.isEmpty()) {
        userInfoDto.setOfferApproverGroup(true);
      }
      if (!employeeOnboardingRepository
          .findByLineManagerId(employeeOnboarding.getEmpId())
          .isEmpty()) {
        userInfoDto.setLineManager(true);
      }
    }

    List<UserRole> roleList = roleRepository.listRole(userInfoDto.getUserId());
    List<UserRoleDto> roleDtoList =
        roleList.stream().map(role -> modelMapper.map(role, UserRoleDto.class)).toList();
    userInfoDto.setRoleDtoList(roleDtoList);
    return userInfoDto;
  }
}
