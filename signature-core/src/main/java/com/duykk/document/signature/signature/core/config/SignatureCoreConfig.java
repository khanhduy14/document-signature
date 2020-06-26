package com.duykk.document.signature.signature.core.config;

import com.duykk.document.signature.common.exception.MyException;
import com.duykk.document.signature.signature.core.service.CertificateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

@ComponentScan({"com.duykk.document.signature.signature.core.service"})
@Configuration
@EnableJpaRepositories(basePackages = "com.duykk.document.signature.signature.core.repository")
@EntityScan("com.duykk.document.signature.signature.core.model")
@Slf4j
public class SignatureCoreConfig {
  @Autowired
  CertificateService certificateService;
  public static KeyStore keyStore;

  @PostConstruct
  void init () {
    try {
      keyStore = KeyStore.getInstance("PKCS12");
      certificateService.init();
    } catch (CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | SignatureException | NoSuchProviderException | InvalidKeyException | IOException | MyException e) {
      e.printStackTrace();
    }
  }
}
