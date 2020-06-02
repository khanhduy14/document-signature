package com.duykk.document.signature.signature.core.model;

import com.duykk.document.signature.common.model.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@EqualsAndHashCode(callSuper = true)
@Data
@Entity
@Table(name = "certificate")
public class CertificateEntity extends BaseEntity {
  @Column(name = "user_id")
  private String userId;

  @Column(name = "certificate_as_char", columnDefinition = "TEXT")
  private String certificateAsChar;
}
