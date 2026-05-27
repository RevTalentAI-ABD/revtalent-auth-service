package com.revtalent.auth_service.controller;

import com.revtalent.auth_service.dto.CompleteProfileRequest;
import com.revtalent.auth_service.dto.LoginRequest;
import com.revtalent.auth_service.dto.RegisterRequest;
import com.revtalent.auth_service.dto.SendOtpRequest;
import com.revtalent.auth_service.dto.VerifyOtpRequest;
import com.revtalent.auth_service.service.AuthService;
import com.revtalent.auth_service.service.OtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@PreAuthorize("permitAll()")
public class AuthController {

    @Autowired private AuthService authService;
    @Autowired private OtpService  otpService;

    // ══════════════════════════════════════════════════════════════════════════
    //  PASSWORD LOGIN
    // ══════════════════════════════════════════════════════════════════════════

    /** POST /api/auth/login — standard password login */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        try {
            return ResponseEntity.ok(authService.login(req));
        } catch (RuntimeException e) {
            return switch (e.getMessage()) {
                case "Invalid credentials"
                        -> ResponseEntity.status(401).body(e.getMessage());
                case "Account is inactive. Please verify OTP."
                        -> ResponseEntity.status(403).body(e.getMessage());
                default -> e.getMessage().contains("locked")
                        ? ResponseEntity.status(429).body(e.getMessage())
                        : ResponseEntity.status(400).body(e.getMessage());
            };
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  OTP FLOW   (/api/auth/email/…)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * POST /api/auth/email/send-otp
     * Body: { "email": "...", "type": "login" | "register" }
     * Sends a 6-digit OTP to the given address.
     */
    @PostMapping("/email/send-otp")
    public ResponseEntity<?> sendOtp(@RequestBody SendOtpRequest req) {
        try {
            authService.sendOtp(req.getEmail(), req.getType());
            return ResponseEntity.ok("OTP sent successfully. Please check your email.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /**
     * POST /api/auth/email/verify-otp
     * Body: { "email": "...", "otp": "123456", "type": "login" | "register" }
     * type=login  → returns JWT auth payload
     * type=register → returns { "verificationToken": "..." } for use with /register/complete
     */
    @PostMapping("/email/verify-otp")
    public ResponseEntity<?> verifyEmailOtp(@RequestBody VerifyOtpRequest req) {
        try {
            return ResponseEntity.ok(
                    authService.verifyEmailOtp(req.getEmail(), req.getOtp(), req.getType()));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  MAGIC LINK FLOW   (/api/auth/email/…)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * POST /api/auth/email/send-magic-link
     * Body: { "email": "...", "type": "login" | "register" }
     * Sends a magic link to the given address.
     */
    @PostMapping("/email/send-magic-link")
    public ResponseEntity<?> sendMagicLink(@RequestBody Map<String, String> body) {
        try {
            authService.sendMagicLink(body.get("email"), body.get("type"));
            return ResponseEntity.ok("Magic link sent. Please check your email.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /**
     * POST /api/auth/email/verify-magic-link  (new canonical URL)
     * Body: { "email": "...", "token": "..." }
     * Verifies the magic link token.
     * login flow  → JWT auth payload
     * register flow → { "verificationToken": "..." }
     */
    @PostMapping("/email/verify-magic-link")
    public ResponseEntity<?> verifyMagicLinkNew(@RequestBody Map<String, String> body) {
        try {
            return ResponseEntity.ok(
                    authService.verifyMagicLink(body.get("email"), body.get("token")));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  REGISTRATION COMPLETION (STEP 3)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * POST /api/auth/register/complete
     * Body: { "email", "verificationToken", "name", "password", "role" }
     * Finalises registration after email verification.
     * Returns JWT auth payload on success.
     */
    @PostMapping("/register/complete")
    public ResponseEntity<?> completeProfile(@RequestBody CompleteProfileRequest req) {
        try {
            return ResponseEntity.ok(authService.completeProfile(req));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  FORGOT PASSWORD
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * POST /api/auth/forgot-password
     * Body: { "email": "..." }
     * Sends a password-reset link. Always returns 200 to prevent enumeration.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> body) {
        if (body.get("email") == null || body.get("email").isBlank()) {
            return ResponseEntity.badRequest().body("Email is required");
        }
        try {
            authService.forgotPassword(body.get("email"));
            return ResponseEntity.ok(
                    "If that email is registered, a reset link has been sent.");
        } catch (Exception e) {
            // Swallow errors to prevent enumeration
            return ResponseEntity.ok(
                    "If that email is registered, a reset link has been sent.");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  LEGACY ENDPOINTS (kept for backwards-compatibility)
    // ══════════════════════════════════════════════════════════════════════════

    /** POST /api/auth/register — legacy password-first registration */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        try {
            return ResponseEntity.ok(authService.register(req));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /** POST /api/auth/verify-email — legacy: triggers OTP for forgot-password flow */
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestBody Map<String, String> body) {
        try {
            authService.verifyEmail(body.get("email"));
            return ResponseEntity.ok("If the email exists, an OTP has been sent.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /** POST /api/auth/reset-password — resets password using OTP */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        if (body.get("email") == null || body.get("email").isBlank()) {
            return ResponseEntity.badRequest().body("Email is required");
        }
        try {
            authService.resetPassword(
                    body.get("email"), body.get("otp"), body.get("newPassword"));
            return ResponseEntity.ok("Password updated successfully");
        } catch (RuntimeException e) {
            return "Invalid credentials".equals(e.getMessage())
                    ? ResponseEntity.status(401).body(e.getMessage())
                    : ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /** POST /api/auth/verify-otp — legacy OTP verification (activates account) */
    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> body) {
        try {
            return ResponseEntity.ok(
                    authService.verifyOtp(body.get("email"), body.get("otp")));
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /** POST /api/auth/resend-otp — resend OTP (legacy; defaults to login type) */
    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@RequestBody Map<String, String> body) {
        if (body.get("email") == null || body.get("email").isBlank()) {
            return ResponseEntity.badRequest().body("Email is required");
        }
        try {
            String type = body.getOrDefault("type", "login");
            otpService.generateAndSendTypedOtp(body.get("email").toLowerCase(), type);
            return ResponseEntity.ok("OTP resent successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Failed to resend OTP");
        }
    }

    /** POST /api/auth/magic-link-request — legacy magic-link request (login) */
    @PostMapping("/magic-link-request")
    public ResponseEntity<?> magicLinkRequest(@RequestBody Map<String, String> body) {
        try {
            authService.sendMagicLink(body.get("email"), "login");
            return ResponseEntity.ok("Magic link sent successfully. Please check your email.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(400).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    /** POST /api/auth/magic-link-verify — legacy magic-link verification */
    @PostMapping("/magic-link-verify")
    public ResponseEntity<?> magicLinkVerify(@RequestBody Map<String, String> body) {
        try {
            return ResponseEntity.ok(
                    authService.verifyMagicLink(body.get("email"), body.get("token")));
        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}
