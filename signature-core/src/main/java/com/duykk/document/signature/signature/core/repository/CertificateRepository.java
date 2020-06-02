package com.duykk.document.signature.signature.core.repository;

import com.duykk.document.signature.signature.core.model.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface CertificateRepository extends JpaRepository<CertificateEntity, String> {
}
