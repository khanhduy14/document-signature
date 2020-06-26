package com.duykk.document.signature.signature.api.controller;


import com.duykk.document.signature.signature.api.api.CertificateController;
import com.duykk.document.signature.signature.core.service.CertificateService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.annotation.RequestScope;

import javax.validation.Valid;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

@RequestMapping("/certificate")
@RestController
@Slf4j
public class CertificateControllerImpl implements CertificateController {
  @Autowired
  CertificateService certificateService;

  @Override
  public ResponseEntity<String> createCertificate(@Valid @RequestParam(value = "userId") String userId) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CryptoException, KeyStoreException, NoSuchProviderException, InvalidKeySpecException {
    return ResponseEntity.ok().body(certificateService.CreateCertificate(userId + "_CA", 30, userId + ".p12", generateUUID()));
  }

  private String generateUUID () {
    return UUID.randomUUID().toString();
  }
}
