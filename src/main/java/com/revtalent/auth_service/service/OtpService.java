package com.revtalent.auth_service.service;

import com.revtalent.auth_service.model.OtpVerification;
import com.revtalent.auth_service.repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;
    private final JavaMailSender mailSender;

    private final Map<String, LocalDateTime> lastSent    = new ConcurrentHashMap<>();
    private final Map<String, Integer>       failedAttempts = new ConcurrentHashMap<>();
    private final SecureRandom               secureRandom   = new SecureRandom();

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.frontend-url:http://localhost:5173}")
    private String frontendUrl;

    // ── Rate-limit helper ─────────────────────────────────────────────────────

    private void checkRateLimit(String key, String friendlyName) {
        LocalDateTime last = lastSent.get(key);
        if (last != null && last.plusMinutes(1).isAfter(LocalDateTime.now())) {
            throw new RuntimeException(
                    "Please wait 1 minute before requesting another " + friendlyName);
        }
    }

    // ── Generate and send OTP (with type) ────────────────────────────────────

    @Transactional
    public void generateAndSendOtp(String email) {
        generateAndSendTypedOtp(email, "login");
    }

    /**
     * Generates a 6-digit OTP and e-mails it to the user.
     *
     * @param email normalised (lowercase) email
     * @param type  "login" | "register" | "forgot-password"
     */
    @Transactional
    public void generateAndSendTypedOtp(String email, String type) {
        checkRateLimit(email + ":" + type, "OTP");

        otpRepository.deleteByEmailAndType(email, type);

        String otp = String.format("%06d", secureRandom.nextInt(1_000_000));

        OtpVerification record = OtpVerification.builder()
                .email(email)
                .otp(otp)
                .type(type)
                .isUsed(false)
                .build();
        otpRepository.save(record);

        String subject, body;
        switch (type) {
            case "register" -> {
                subject = "RevTalent — Verify Your Email";
                body = "Hello!\n\n"
                        + "Your email verification code is: " + otp + "\n\n"
                        + "This code is valid for 5 minutes.\n"
                        + "Do not share this with anyone.\n\n"
                        + "Team RevTalent";
            }
            case "forgot-password" -> {
                subject = "RevTalent — Password Reset Code";
                body = "Hello!\n\n"
                        + "Your password reset code is: " + otp + "\n\n"
                        + "This code is valid for 5 minutes.\n"
                        + "If you did not request a reset, you can ignore this email.\n\n"
                        + "Team RevTalent";
            }
            default -> {  // "login"
                subject = "RevTalent — Your OTP Code";
                body = "Hello!\n\n"
                        + "Your OTP for RevTalent login is: " + otp + "\n\n"
                        + "This OTP is valid for 5 minutes.\n"
                        + "Do not share this with anyone.\n\n"
                        + "Team RevTalent";
            }
        }

        sendEmail(email, subject, body, otp, null);
        lastSent.put(email + ":" + type, LocalDateTime.now());
    }

    // ── Generate and send Magic Link (with type) ──────────────────────────────

    @Transactional
    public void generateAndSendMagicLink(String email) {
        generateAndSendTypedMagicLink(email, "login");
    }

    /**
     * Generates a secure token and e-mails it as a clickable magic link.
     *
     * @param email normalised email
     * @param type  "login" | "register"
     */
    @Transactional
    public void generateAndSendTypedMagicLink(String email, String type) {
        checkRateLimit(email + ":magic:" + type, "Magic Link");

        otpRepository.deleteByEmailAndType(email, "magic-" + type);

        String token = java.util.UUID.randomUUID().toString()
                + java.util.UUID.randomUUID().toString();
        token = token.replace("-", "");

        OtpVerification record = OtpVerification.builder()
                .email(email)
                .otp(token)
                .type("magic-" + type)   // e.g. "magic-login" or "magic-register"
                .isUsed(false)
                .build();
        otpRepository.save(record);

        String path   = "login".equals(type) ? "/magic-login" : "/magic-register";
        String link   = frontendUrl + path + "?email=" + email + "&token=" + token;
        String subject, body;

        if ("register".equals(type)) {
            subject = "RevTalent — Verify Your Email";
            body    = "Hello!\n\n"
                    + "Click the link below to verify your email and complete your RevTalent registration:\n"
                    + link + "\n\n"
                    + "This link is valid for 5 minutes.";
        } else {
            subject = "RevTalent — Your Magic Login Link";
            body    = "Hello!\n\n"
                    + "Click the link below to securely log into your RevTalent account:\n"
                    + link + "\n\n"
                    + "This link is valid for 5 minutes.";
        }

        sendEmail(email, subject, body, null, link);
        lastSent.put(email + ":magic:" + type, LocalDateTime.now());
    }

    // ── Forgot password (sends reset link) ───────────────────────────────────

    // BEFORE (lines 162–193)
    /**
     * Sends a password-reset link to the given email.
     * Uses the same OTP mechanism under the hood (type="forgot-password").
     */
    @Transactional
    public void sendForgotPasswordLink(String email) {
        checkRateLimit(email + ":forgot-password", "password reset email");

        otpRepository.deleteByEmailAndType(email, "forgot-password");

        String token = java.util.UUID.randomUUID().toString()
                + java.util.UUID.randomUUID().toString();
        token = token.replace("-", "");

        OtpVerification record = OtpVerification.builder()
                .email(email)
                .otp(token)
                .type("forgot-password")
                .isUsed(false)
                .build();
        otpRepository.save(record);

        String link = frontendUrl + "/reset-password?email=" + email + "&token=" + token;
        String subject = "RevTalent — Reset Your Password";
        String body = "Hello!\n\n"
                + "Click the link below to reset your RevTalent password:\n"
                + link + "\n\n"
                + "This link is valid for 5 minutes.\n"
                + "If you did not request a password reset, please ignore this email.\n\n"
                + "Team RevTalent";

        sendEmail(email, subject, body, null, link);
        lastSent.put(email + ":forgot-password", LocalDateTime.now());
    }
    // ── Verify OTP (generic, matches on most-recent record) ──────────────────

    @Transactional
    public boolean verifyOtp(String email, String otp) {
        return verifyTypedOtp(email, otp, null);
    }

    /**
     * Verifies an OTP/token.
     *
     * @param type nullable — if null, matches the most-recent record for the email
     */
    @Transactional
    public boolean verifyTypedOtp(String email, String otp, String type) {
        OtpVerification record = (type != null)
                ? otpRepository.findTopByEmailAndTypeOrderByCreatedAtDesc(email, type)
                               .orElseThrow(() -> new RuntimeException("No verification found for this email"))
                : otpRepository.findTopByEmailOrderByCreatedAtDesc(email)
                               .orElseThrow(() -> new RuntimeException("No OTP found for this email"));

        if (record.isUsed()) {
            throw new RuntimeException("OTP already used");
        }
        if (LocalDateTime.now().isAfter(record.getExpiresAt())) {
            throw new RuntimeException("OTP expired. Please request a new one");
        }
        if (!record.getOtp().equals(otp)) {
            int attempts = failedAttempts.getOrDefault(email, 0) + 1;
            if (attempts >= 5) {
                record.setUsed(true);
                otpRepository.save(record);
                failedAttempts.remove(email);
                throw new RuntimeException("Too many failed attempts. OTP invalidated.");
            }
            failedAttempts.put(email, attempts);
            return false;
        }

        record.setUsed(true);
        otpRepository.save(record);
        failedAttempts.remove(email);
        return true;
    }

    // ── Internal mail helper ─────────────────────────────────────────────────

    private void sendEmail(String to, String subject, String body,
                           String devOtp, String devLink) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(fromEmail);
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(body);
        try {
            mailSender.send(msg);
        } catch (Exception e) {
            System.err.println("=====================================================");
            System.err.println("SMTP failed for " + to + ": " + e.getMessage());
            if (devOtp  != null) System.err.println("DEV OTP:  " + devOtp);
            if (devLink != null) System.err.println("DEV LINK: " + devLink);
            System.err.println("=====================================================");
            // Intentionally swallowed — keeps dev workflow functional
        }
    }
}
