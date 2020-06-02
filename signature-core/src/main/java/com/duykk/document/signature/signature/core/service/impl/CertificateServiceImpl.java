package com.duykk.document.signature.signature.core.service.impl;

import com.duykk.document.signature.signature.core.service.CertificateService;
import com.duykk.document.signature.signature.core.utils.X509CertificateGenerator;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@Service
public class CertificateServiceImpl implements CertificateService {
  private static X509CertificateGenerator x509CertificateGenerator;
  private static final String CA_ROOT_FILE = "root.p12";
  private static final String CA_PASSWORD = "12345678";
  private static final String CA_ALIAS = "senderKeyPair";
  private static final boolean USE_BCAPI = false;

  public CertificateServiceImpl() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, SignatureException, NoSuchProviderException, InvalidKeyException, IOException {
    x509CertificateGenerator = new X509CertificateGenerator(CA_ROOT_FILE, CA_PASSWORD, CA_ALIAS, USE_BCAPI);
  }

  @Override
  public boolean CreateCertificate(String dn, int validityDays, String exportFile, String exportPassword, String userId) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CryptoException, NoSuchProviderException, KeyStoreException, InvalidKeySpecException {

    return x509CertificateGenerator.createCertificate(dn, validityDays, exportFile, exportPassword);
  }
}
