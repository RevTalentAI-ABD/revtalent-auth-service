package com.revtalent.auth_service.service;

import com.revtalent.auth_service.model.OtpVerification;
import com.revtalent.auth_service.repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;
    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")   // ← pulls from application.properties automatically
    private String fromEmail;

    // ── Generate and send OTP ─────────────────────────────────────────────────

    @Transactional
    public void generateAndSendOtp(String email) {
        // Delete any existing OTP for this email
        otpRepository.deleteByEmail(email);

        // Generate 6-digit OTP
        String otp = String.format("%06d", new Random().nextInt(999999));

        // Save to DB
        OtpVerification otpRecord = OtpVerification.builder()
                .email(email)
                .otp(otp)
                .isUsed(false)
                .build();
        otpRepository.save(otpRecord);

        // Send email
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);                        // ← ADDED: must match spring.mail.username
        message.setTo(email);
        message.setSubject("RevTalent — Your OTP Code");
        message.setText(
                "Hello!\n\n" +
                        "Your OTP for RevTalent login is: " + otp + "\n\n" +
                        "This OTP is valid for 5 minutes.\n" +
                        "Do not share this with anyone.\n\n" +
                        "Team RevTalent"
        );
        mailSender.send(message);
    }

    // ── Verify OTP ────────────────────────────────────────────────────────────

    @Transactional
    public boolean verifyOtp(String email, String otp) {
        OtpVerification record = otpRepository
                .findTopByEmailOrderByCreatedAtDesc(email)
                .orElseThrow(() -> new RuntimeException("No OTP found for this email"));

        // Check if already used
        if (record.isUsed()) {
            throw new RuntimeException("OTP already used");
        }

        // Check if expired
        if (LocalDateTime.now().isAfter(record.getExpiresAt())) {
            throw new RuntimeException("OTP expired. Please request a new one");
        }

        // Check if matches
        if (!record.getOtp().equals(otp)) {
            return false; // wrong OTP
        }

        // Mark as used
        record.setUsed(true);
        otpRepository.save(record);
        return true; // correct OTP
    }
}
