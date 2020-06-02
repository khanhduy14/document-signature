package com.duykk.document.signature.signature.api.controller;


import com.duykk.document.signature.signature.api.api.CertificateController;
import com.duykk.document.signature.signature.core.service.CertificateService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@RestController
@Slf4j
public class CertificateControllerImpl implements CertificateController {
  @Autowired
  CertificateService certificateService;

  @Override
  public ResponseEntity<String> createCertificate(@Valid String userId) {
    try {
      certificateService.CreateCertificate("Test CN", 30, "test.p12", "test", "");
    } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | CryptoException | NoSuchProviderException | KeyStoreException | InvalidKeySpecException e) {
      e.printStackTrace();
    }
    return null;
  }
}
