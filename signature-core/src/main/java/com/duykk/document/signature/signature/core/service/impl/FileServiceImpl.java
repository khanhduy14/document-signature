package com.duykk.document.signature.signature.core.service.impl;

import com.duykk.document.signature.common.exception.MyException;
import com.duykk.document.signature.signature.core.model.FileEntity;
import com.duykk.document.signature.signature.core.repository.FileRepository;
import com.duykk.document.signature.signature.core.service.FileService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
@Slf4j
public class FileServiceImpl implements FileService {
  @Autowired
  FileRepository repository;

  @Override
  public String saveUploadFiles(final MultipartFile uploadFile) throws IOException {
    final byte[] bytes = uploadFile.getBytes();
    FileEntity fileEntity = new FileEntity();
    fileEntity.setRawData(bytes);
    repository.save(fileEntity);
    return fileEntity.getId();
  }

  @Override
  public FileEntity getFileById(String fileId) throws MyException {
    return repository.findById(fileId).orElseThrow(
            () -> new MyException(HttpStatus.NOT_FOUND, "File Not Found"));
  }

  @Override
  public void saveFile(FileEntity fileEntity) {
    repository.save(fileEntity);
  }

  @Override
  public FileEntity getByVerifyCode(String verifyCode) throws MyException {
    return repository.getByVerifyCode(verifyCode).orElseThrow(() -> new MyException(HttpStatus.NOT_FOUND, "Not Found"));
  }
}
