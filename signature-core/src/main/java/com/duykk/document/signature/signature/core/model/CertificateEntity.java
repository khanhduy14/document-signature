package com.duykk.document.signature.signature.core.model;

import com.duykk.document.signature.common.model.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Lob;
import javax.persistence.Table;

@EqualsAndHashCode(callSuper = true)
@Data
@Entity
@Table(name = "certificate")
public class CertificateEntity extends BaseEntity {
  @Column(name = "certificate_as_char", columnDefinition = "TEXT")
  private String certificateAsChar;

  @Lob
  @Column(name = "file_data")
  private byte[] data;

  @Column(name = "file_name")
  private String fileName;

  @Column(name = "alias_name")
  private String aliasName;

  @Column(name = "password")
  private String password;

  public static CertificateEntity of(byte[] data, String fileName, String aliasName, String password) {
    CertificateEntity certificateEntity = new CertificateEntity();
    certificateEntity.setAliasName(aliasName);
    certificateEntity.setData(data);
    certificateEntity.setFileName(fileName);
    certificateEntity.setPassword(password);
    return certificateEntity;
  }
}
