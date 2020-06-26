package com.duykk.document.signature.signature.api.controller;

import com.duykk.document.signature.common.exception.MyException;
import com.duykk.document.signature.signature.api.api.FileController;
import com.duykk.document.signature.signature.core.model.FileEntity;
import com.duykk.document.signature.signature.core.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.io.IOException;

@RestController
@RequestMapping("/file")
public class FileControllerImpl implements FileController {
  @Autowired
  FileService fileService;

  @Override
  public ResponseEntity<String> upload(final MultipartFile uploadfile) throws IOException {
    return ResponseEntity.ok().body(fileService.saveUploadFiles(uploadfile));
  }

  @Override
  public ResponseEntity<Resource> download(@Valid String fileId) throws IOException, MyException {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=sign.txt");
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    FileEntity fileEntity = fileService.getFileById(fileId);
    Resource resource = new ByteArrayResource(fileEntity.getSignData());
    return ResponseEntity.ok()
        .headers(headers)
        .contentLength(fileEntity.getSignData().length)
        .contentType(MediaType.parseMediaType("application/octet-stream")).body(resource);
  }
}
