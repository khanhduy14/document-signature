package com.duykk.document.signature.signature.core.model;

import com.duykk.document.signature.common.model.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

@Data
@Entity
@EqualsAndHashCode(callSuper = true)
@Table(name = "file")
public class FileEntity extends BaseEntity {
  @Column(name = "raw_data")
  private byte[] rawData;

  @Column(name = "sign_data")
  private byte[] signData;

  @Column(name = "verify_code")
  private String verifyCode;

  public static FileEntity of(byte[] rawData, byte[] signData) {
    FileEntity fileEntity = new FileEntity();
    fileEntity.setRawData(rawData);
    fileEntity.setSignData(signData);
    return fileEntity;
  }
}
