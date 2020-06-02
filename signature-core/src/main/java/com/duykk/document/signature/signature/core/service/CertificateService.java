package com.duykk.document.signature.signature.core.service;

import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public interface CertificateService {
  boolean CreateCertificate(String dn, int validityDays, String exportFile, String exportPassword, String userId) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CryptoException, NoSuchProviderException, KeyStoreException, InvalidKeySpecException;
}
