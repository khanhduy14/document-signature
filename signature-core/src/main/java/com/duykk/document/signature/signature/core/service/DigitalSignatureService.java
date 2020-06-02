package com.duykk.document.signature.signature.core.service;

public interface DigitalSignatureService {
  void digitalSignatureSigning() throws Exception ;
  void digitalSignatureVerify() throws Exception ;
  void encryptData() throws Exception;
}
