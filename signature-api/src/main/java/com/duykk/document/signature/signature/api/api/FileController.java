package com.duykk.document.signature.signature.api.api;

import com.duykk.document.signature.common.exception.MyException;
import io.swagger.annotations.*;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.io.IOException;

public interface FileController {
  @PostMapping(value = "/upload", produces = MediaType.APPLICATION_JSON_VALUE)
  @ApiOperation(
          value = "Upload File",
          authorizations = {@Authorization(value = "JwtToken")})
  @ApiResponses(
          value = {@ApiResponse(code = 200, message = "Upload File")})
  @CrossOrigin
  ResponseEntity<String> upload(@RequestPart(value = "file") final MultipartFile uploadfile) throws IOException;

  @GetMapping(value = "/download", produces = MediaType.APPLICATION_JSON_VALUE)
  @ApiOperation(
          value = "Download File",
          authorizations = {@Authorization(value = "JwtToken")})
  @ApiResponses(
          value = {@ApiResponse(code = 200, message = "Download File")})
  @CrossOrigin
  ResponseEntity<Resource> download(@ApiParam(value = "fileId", required = true) @Valid String fileId) throws IOException, MyException;
}
