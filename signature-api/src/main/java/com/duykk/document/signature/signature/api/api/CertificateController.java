package com.duykk.document.signature.signature.api.api;

import io.swagger.annotations.*;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;

import javax.validation.Valid;

public interface CertificateController {
  @PostMapping(value = "/createCertificate", produces = MediaType.APPLICATION_JSON_VALUE)
  @ApiOperation(
          value = "Create Certificate",
          authorizations = {@Authorization(value = "JwtToken")})
  @ApiResponses(
          value = {@ApiResponse(code = 200, message = "Create Certificate Successfully.")})
  ResponseEntity<String> createCertificate(
          @ApiParam(value = "userId", required = true) @Valid String userId);
}
