package com.duykk.document.signature.signature.core.service;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public interface KeyStoreService {
  void createEmptyKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException;
  void loadKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException;
  void setEntry(String alias, KeyStore.SecretKeyEntry secretKeyEntry, KeyStore.ProtectionParameter protectionParameter) throws KeyStoreException;
  public KeyStore.Entry getEntry(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException;
  public void setKeyEntry(String alias, PrivateKey privateKey, String keyPassword, Certificate[] certificateChain) throws KeyStoreException;
  public void setCertificateEntry(String alias, Certificate certificate) throws KeyStoreException;
  public Certificate getCertificate(String alias) throws KeyStoreException;
  public void deleteEntry(String alias) throws KeyStoreException;
  public void deleteKeyStore() throws KeyStoreException, IOException;
  public KeyStore getKeyStore();
}
