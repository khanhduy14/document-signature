package com.duykk.document.signature.signature.core.service.impl;

import com.duykk.document.signature.signature.core.service.KeyStoreService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

@Service
@Slf4j
public class KeyStoreServiceImpl implements KeyStoreService {
  private KeyStore keyStore;

  private String keyStoreName;
  private String keyStoreType;
  private String keyStorePassword;

  @Override
  public void createEmptyKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
    if(keyStoreType ==null || keyStoreType.isEmpty()){
      keyStoreType = KeyStore.getDefaultType();
    }
    keyStore = KeyStore.getInstance(keyStoreType);
    //load
    char[] pwdArray = keyStorePassword.toCharArray();
    keyStore.load(null, pwdArray);

    // Save the keyStore
    FileOutputStream fos = new FileOutputStream(keyStoreName);
    keyStore.store(fos, pwdArray);
    fos.close();
  }

  public void loadKeyStore() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
    char[] pwdArray = keyStorePassword.toCharArray();
    keyStore.load(new FileInputStream(keyStoreName), pwdArray);
  }

  public void setEntry(String alias, KeyStore.SecretKeyEntry secretKeyEntry, KeyStore.ProtectionParameter protectionParameter) throws KeyStoreException {
    keyStore.setEntry(alias, secretKeyEntry, protectionParameter);
  }

  public KeyStore.Entry getEntry(String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
    KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keyStorePassword.toCharArray());
    return keyStore.getEntry(alias, protParam);
  }

  public void setKeyEntry(String alias, PrivateKey privateKey, String keyPassword, Certificate[] certificateChain) throws KeyStoreException {
    keyStore.setKeyEntry(alias, privateKey, keyPassword.toCharArray(), certificateChain);
  }

  public void setCertificateEntry(String alias, Certificate certificate) throws KeyStoreException {
    keyStore.setCertificateEntry(alias, certificate);
  }

  public Certificate getCertificate(String alias) throws KeyStoreException {
    return keyStore.getCertificate(alias);
  }

  public void deleteEntry(String alias) throws KeyStoreException {
    keyStore.deleteEntry(alias);
  }

  public void deleteKeyStore() throws KeyStoreException, IOException {
    Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      keyStore.deleteEntry(alias);
    }
    keyStore = null;
    Files.delete(Paths.get(keyStoreName));
  }

  public KeyStore getKeyStore() {
    return this.keyStore;
  }
}
