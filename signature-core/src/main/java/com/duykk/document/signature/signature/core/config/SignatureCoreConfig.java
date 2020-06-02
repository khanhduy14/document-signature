package com.duykk.document.signature.signature.core.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@ComponentScan({"com.duykk.document.signature.signature.core.service"})
@Configuration
@EnableJpaRepositories(basePackages = "com.duykk.document.signature.signature.core.repository")
@EntityScan("com.duykk.document.signature.signature.core.model")
@Slf4j
public class SignatureCoreConfig {
}
