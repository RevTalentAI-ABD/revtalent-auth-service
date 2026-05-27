package com.revtalent.auth_service.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "otp_verification")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class OtpVerification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String otp;

    @Column(name = "is_used", nullable = false)
    private boolean isUsed = false;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    /**
     * Discriminates OTP purpose: "login", "register", "forgot-password", "magic-link"
     */
    @Column(name = "type", length = 20)
    private String type;

    /**
     * JSON blob used to carry pending registration data (name, password, role)
     * until email is verified via /api/auth/register/complete.
     */
    @Column(name = "pending_data", columnDefinition = "TEXT")
    private String pendingData;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        expiresAt = LocalDateTime.now().plusMinutes(5);
    }
}