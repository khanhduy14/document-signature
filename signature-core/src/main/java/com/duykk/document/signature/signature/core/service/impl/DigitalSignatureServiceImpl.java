package com.duykk.document.signature.signature.core.service.impl;

import com.duykk.document.signature.signature.core.service.DigitalSignatureService;
import com.duykk.document.signature.signature.core.utils.CryptoUtils;
import com.duykk.document.signature.signature.core.utils.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

@Service
@Slf4j
public class DigitalSignatureServiceImpl implements DigitalSignatureService {

  public void digitalSignatureSigning() throws Exception {
    PrivateKey privateKey = Utils.getPrivateKey();

    Signature signature = Signature.getInstance(Utils.SIGNING_ALGORITHM);
    signature.initSign(privateKey);

    byte[] messageBytes =
        Files.readAllBytes(Paths.get("src/test/resources/digitalsignature/message.txt"));

    signature.update(messageBytes);
    byte[] digitalSignature = signature.sign();
    Files.write(Paths.get("target/digital_signature_2"), digitalSignature);
    log.info("Signing Done >>>>>>>");
    log.info(new String(digitalSignature));
  }

  @Override
  public void digitalSignatureVerify() throws Exception {
    PublicKey publicKey = Utils.getPublicKey();

    byte[] sig = Files.readAllBytes(Paths.get("target/digital_signature_2"));

    Signature signature = Signature.getInstance(Utils.SIGNING_ALGORITHM);
    signature.initVerify(publicKey);

    byte[] messageBytes = Files.readAllBytes(Paths.get("src/test/resources/digitalsignature/message.txt"));
    log.info(String.valueOf(messageBytes));
    signature.update(messageBytes);

    boolean isCorrect = signature.verify(sig);
    log.info("Signature " + (isCorrect ? "correct" : "incorrect"));
  }

  @Override
  public void encryptData() throws Exception {
    byte[] messageBytes = Files.readAllBytes(Paths.get("src/test/resources/digitalsignature/message.txt"));
    String certificatePath = "src/main/resources/test.cer";
    String privateKeyPath = "src/main/resources/test.p12";
    char[] p12Password = "password".toCharArray();
    char[] keyPassword = "changeit".toCharArray();
    KeyStore keystore = KeyStore.getInstance("PKCS12");
    keystore.load(new FileInputStream("sender_keystore.p12"), keyPassword);
    PrivateKey privateKey = (PrivateKey) keystore.getKey("senderKeyPair", keyPassword);
    byte[] rawData = CryptoUtils.decryptData(messageBytes, privateKey);
    log.info(Arrays.toString(rawData));
  }
}
