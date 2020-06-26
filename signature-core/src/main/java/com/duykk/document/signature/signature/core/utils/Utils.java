package com.duykk.document.signature.signature.core.utils;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class Utils {
  private static final String STORE_TYPE = "PKCS12";
  private static final char[] PASSWORD = "changeit".toCharArray();

  public static final String SIGNING_ALGORITHM = "SHA256withRSA";

  private static final String RECEIVER_KEYSTORE = "receiver_keystore.p12";
  private static final String RECEIVER_ALIAS = "receiverKeyPair";

  public static PrivateKey getPrivateKey(byte[] caData, String aliasName, String password) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
    InputStream inputStream = new ByteArrayInputStream(caData);
    keyStore.load(inputStream, password.toCharArray());
    return (PrivateKey) keyStore.getKey(aliasName, password.toCharArray());
  }

  public static PublicKey getPublicKey(byte[] caData, String aliasName, String password) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(STORE_TYPE);
    InputStream inputStream = new ByteArrayInputStream(caData);
    keyStore.load(inputStream, password.toCharArray());
    Certificate certificate = keyStore.getCertificate(aliasName);
    return certificate.getPublicKey();
  }

  public static byte[] convertInputStreamToByteArray (InputStream file) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    int nRead;
    byte[] data = new byte[16384];

    while ((nRead = file.read(data, 0, data.length)) != -1) {
      buffer.write(data, 0, nRead);
    }

    return buffer.toByteArray();
  }
}
