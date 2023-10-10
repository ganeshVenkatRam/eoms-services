package com.optimum.eoms.security.entity;

import com.optimum.eoms.model.common.entity.Auditable;
import com.optimum.eoms.security.constants.SecurityConstants.TokenType;
import jakarta.persistence.*;
import java.sql.Timestamp;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;

/** used to provide entity for token */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_token")
public class UserToken extends Auditable<Date> {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "id")
  private Integer id;

  @Column(name = "access_token", unique = true, length = 4096)
  private String accessToken;

  @Enumerated(EnumType.STRING)
  @Column(name = "token_type")
  private TokenType tokenType;

  @Column(name = "revoked")
  private Boolean revoked;

  @Column(name = "expired")
  private Boolean expired;

  @Column(name = "created_date", updatable = false)
  @CreatedDate
  private Timestamp createdDate;

  @Column(name = "expired_date", updatable = false)
  private Timestamp expiredDate;

  @Column(name = "user_id")
  private Long userId;
}
