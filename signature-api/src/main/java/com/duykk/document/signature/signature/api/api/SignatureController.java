package com.duykk.document.signature.signature.api.api;

import io.swagger.annotations.*;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;

public interface SignatureController {
  @PostMapping(value = "/sign", produces = MediaType.APPLICATION_JSON_VALUE)
  @ApiOperation(
          value = "Sign Document",
          authorizations = {@Authorization(value = "JwtToken")})
  @ApiResponses(
          value = {@ApiResponse(code = 200, message = "Sign Document")})
  @CrossOrigin
  ResponseEntity<String> sing(
          @ApiParam(value = "userId", required = true) @Valid String userId, @ApiParam(value = "fileId", required = true) @Valid String fileId) throws Exception;

  @PostMapping(value = "/verify", produces = MediaType.APPLICATION_JSON_VALUE)
  @ApiOperation(
          value = "Verify Document",
          authorizations = {@Authorization(value = "JwtToken")})
  @ApiResponses(
          value = {@ApiResponse(code = 200, message = "Verify Document")})
  @CrossOrigin
  ResponseEntity<Boolean> verify(
          @ApiParam(value = "userId", required = true) @Valid String userId, @ApiParam(value = "verifyCode", required = true) @Valid String verifyCode, @RequestPart(value = "file") final MultipartFile uploadfile) throws Exception;
}
