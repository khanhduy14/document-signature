package com.duykk.document.signature.signature.core.service.impl;

import com.duykk.document.signature.common.exception.MyException;
import com.duykk.document.signature.signature.core.model.CertificateEntity;
import com.duykk.document.signature.signature.core.repository.CertificateRepository;
import com.duykk.document.signature.signature.core.service.CertificateService;
import com.duykk.document.signature.signature.core.utils.Utils;
import com.duykk.document.signature.signature.core.utils.X509CertificateGenerator;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@Service
@Slf4j
public class CertificateServiceImpl implements CertificateService {
  @Autowired
  CertificateRepository certificateRepository;

  private static X509CertificateGenerator x509CertificateGenerator;
  private static final String CA_ROOT_FILE = "root.p12";
  private static final boolean USE_BCAPI = false;

  public CertificateServiceImpl() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException, MyException {
  }

  @Override
  public String CreateCertificate(String dn, int validityDays, String exportFile, String exportPassword) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CryptoException, NoSuchProviderException, KeyStoreException, InvalidKeySpecException {
    if (x509CertificateGenerator.createCertificate(dn, validityDays, exportFile, exportPassword)) {
      InputStream file = new FileInputStream(exportFile);
      String cerId = createRootCertificate(file, exportFile, exportPassword, dn, validityDays);
      File fileDelete = new File(exportFile);
      if (fileDelete.delete()) {
        log.info("File deleted successfully");
      }
      else
      {
        log.info("Failed to delete the file");
      }
      return cerId;
    }
    return null;
  }

  @Override
  public String createRootCertificate(InputStream file, String fileName, String filePassword, String aliasName, int validityDays) throws IOException {
    CertificateEntity certificateEntity = CertificateEntity.of(Utils.convertInputStreamToByteArray(file), fileName, aliasName, filePassword);

    certificateRepository.save(certificateEntity);
    return certificateEntity.getId();
  }

  @Override
  public void init() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException, MyException {
    try {
      CertificateEntity certificateEntity = certificateRepository.findFirstByFileName(CA_ROOT_FILE);
      x509CertificateGenerator = new X509CertificateGenerator(CA_ROOT_FILE, certificateEntity.getData(), certificateEntity.getPassword(), certificateEntity.getAliasName(), USE_BCAPI);
    } catch (Exception ex) {
      throw new MyException(HttpStatus.BAD_REQUEST, "Root CA Not Found");
    }
  }

  @Override
  public CertificateEntity getCertificationByUserId(String userId) {
    return certificateRepository.findFirstByFileName(userId + ".p12");
  }
}
