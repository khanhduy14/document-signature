package com.duykk.document.signature.signature.api;

import com.duykk.document.signature.signature.core.config.EnableSignatureCore;
import com.duykk.document.signature.signature.core.service.CertificateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableSignatureCore
@Slf4j
@EnableTransactionManagement
public class SignatureApiApplication implements CommandLineRunner {
  @Autowired
  CertificateService certificateService;

  public static void main(String[] args) {
    SpringApplication.run(SignatureApiApplication.class, args);
  }

  @Override
  public void run(String... args) throws Exception {
//    InputStream file = new FileInputStream("signature-api/root.p12");
//    certificateService.createRootCertificate(file);
  }
}
