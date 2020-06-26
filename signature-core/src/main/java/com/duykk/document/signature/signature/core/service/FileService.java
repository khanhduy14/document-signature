package com.duykk.document.signature.signature.core.service;

import com.duykk.document.signature.common.exception.MyException;
import com.duykk.document.signature.signature.core.model.FileEntity;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface FileService {
  String saveUploadFiles(final MultipartFile uploadFile) throws IOException;
  FileEntity getFileById(String fileId) throws MyException;
  void saveFile(FileEntity fileEntity);
  FileEntity getByVerifyCode(String verifyCode) throws MyException;
}
