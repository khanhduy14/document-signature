package com.duykk.document.signature.signature.api.api;

import io.swagger.annotations.*;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.validation.Valid;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public interface CertificateController {
  @PostMapping(value = "/createCertificate", produces = MediaType.APPLICATION_JSON_VALUE)
  @ApiOperation(
          value = "Create Certificate",
          authorizations = {@Authorization(value = "JwtToken")})
  @ApiResponses(
          value = {@ApiResponse(code = 200, message = "Create Certificate Successfully.")})
  @CrossOrigin
  ResponseEntity<String> createCertificate(
          @ApiParam(value = "userId", required = true) @Valid String userId) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CryptoException, KeyStoreException, NoSuchProviderException, InvalidKeySpecException;
}
