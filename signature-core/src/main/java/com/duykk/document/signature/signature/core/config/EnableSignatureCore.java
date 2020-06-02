package com.duykk.document.signature.signature.core.config;

import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Import({SignatureCoreConfig.class})
@Target(ElementType.TYPE)
public @interface EnableSignatureCore {
}
