package com.duykk.document.signature.signature.core.service;

import com.duykk.document.signature.common.exception.MyException;
import com.duykk.document.signature.signature.core.model.CertificateEntity;
import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public interface CertificateService {
  String CreateCertificate(String dn, int validityDays, String exportFile, String exportPassword) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CryptoException, NoSuchProviderException, KeyStoreException, InvalidKeySpecException;
  String createRootCertificate(InputStream file, String fileName, String filePassword, String aliasName, int validityDays) throws IOException;
  void init() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException, MyException;
  CertificateEntity getCertificationByUserId(String userId);
}
