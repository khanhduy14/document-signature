package com.duykk.document.signature.signature.core.repository;

import com.duykk.document.signature.signature.core.model.FileEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface FileRepository extends JpaRepository<FileEntity, String> {
  Optional<FileEntity> getByVerifyCode(String verifyCode);
}
