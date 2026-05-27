package com.revtalent.auth_service.repository;

import com.revtalent.auth_service.model.OtpVerification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<OtpVerification, Long> {
    Optional<OtpVerification> findTopByEmailOrderByCreatedAtDesc(String email);
    Optional<OtpVerification> findTopByEmailAndTypeOrderByCreatedAtDesc(String email, String type);
    void deleteByEmail(String email);
    void deleteByEmailAndType(String email, String type);
}