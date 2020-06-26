package com.duykk.document.signature.signature.core.service;

public interface DigitalSignatureService {
  byte[] digitalSignatureSigning(byte[] data, String caAliasName, String caPassword, byte[] caData) throws Exception ;
  boolean digitalSignatureVerify(byte[] data, byte[] rawData, String caAliasName, String caPassword, byte[] caData) throws Exception ;
  void encryptData() throws Exception;
}
