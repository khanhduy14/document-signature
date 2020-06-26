package com.duykk.document.signature.signature.api.controller;

import com.duykk.document.signature.signature.api.api.SignatureController;
import com.duykk.document.signature.signature.core.model.CertificateEntity;
import com.duykk.document.signature.signature.core.model.FileEntity;
import com.duykk.document.signature.signature.core.service.CertificateService;
import com.duykk.document.signature.signature.core.service.DigitalSignatureService;
import com.duykk.document.signature.signature.core.service.FileService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.util.UUID;

@RequestMapping("/signature")
@RestController
@Slf4j
public class SignatureControllerImpl extends BaseController implements SignatureController {
  @Autowired
  DigitalSignatureService digitalSignatureService;

  @Autowired
  FileService fileService;

  @Autowired CertificateService certificateService;

  @Override
  public ResponseEntity<String> sing(@Valid String userId, @Valid String fileId) throws Exception {
    FileEntity fileEntity = fileService.getFileById(fileId);
    CertificateEntity certificateEntity = certificateService.getCertificationByUserId(userId);
    fileEntity.setSignData(
        digitalSignatureService.digitalSignatureSigning(
            fileEntity.getRawData(),
            certificateEntity.getAliasName(),
            certificateEntity.getPassword(),
            certificateEntity.getData()));
    String verifyCode = UUID.randomUUID().toString();
    fileEntity.setVerifyCode(verifyCode);
    fileService.saveFile(fileEntity);
    return ResponseEntity.ok().body(verifyCode);
  }

  @Override
  public ResponseEntity<Boolean> verify(@Valid String userId, @Valid String verifyCode, final MultipartFile uploadfile)
      throws Exception {
    final byte[] bytes = uploadfile.getBytes();
    FileEntity fileEntity = fileService.getByVerifyCode(verifyCode);
    CertificateEntity certificateEntity = certificateService.getCertificationByUserId(userId);
    return ResponseEntity.ok()
        .body(
            digitalSignatureService.digitalSignatureVerify(
                fileEntity.getSignData(),
                bytes,
                certificateEntity.getAliasName(),
                certificateEntity.getPassword(),
                certificateEntity.getData()));
  }
}
