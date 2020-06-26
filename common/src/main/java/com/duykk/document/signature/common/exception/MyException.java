package com.duykk.document.signature.common.exception;

import org.springframework.http.HttpStatus;

public class MyException extends Exception {
  protected final HttpStatus httpStatus;

  protected final String messageCode;

  protected transient Object[] args;

  public MyException(HttpStatus httpStatus, String messageCode) {
    super(messageCode);
    this.httpStatus = httpStatus;
    this.messageCode = messageCode;
  }

  public MyException(HttpStatus httpStatus, String messageCode, Object[] args) {
    super(messageCode);
    this.httpStatus = httpStatus;
    this.messageCode = messageCode;
    this.args = args;
  }
}
