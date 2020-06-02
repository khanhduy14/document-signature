package com.duykk.document.signature.common.model;

import lombok.Data;
import org.springframework.data.annotation.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.Column;
import javax.persistence.EntityListeners;
import javax.persistence.MappedSuperclass;
import javax.persistence.PrePersist;
import java.util.UUID;

@Data
@EntityListeners({AuditingEntityListener.class})
@MappedSuperclass
public class BaseEntity {
  @Id
  private String id;

  @Column(name = "name")
  private String name;

  @CreatedDate
  @Column(name = "create_at")
  private Long createAt;

  @CreatedBy
  @Column(name = "create_by")
  private String createBy;

  @LastModifiedDate
  @Column(name = "modify_at")
  private Long modifyAt;

  @LastModifiedBy
  @Column(name = "modify_by")
  private String modifyBy;

  @PrePersist
  private void ensureId() {
    this.setId(UUID.randomUUID().toString());
  }

  public String getId() {
    if (id == null) {
      id = UUID.randomUUID().toString();
    }

    return id;
  }
}


