package com.revtalent.auth_service.dto;

import lombok.Data;

/**
 * Payload for POST /api/auth/register/complete.
 * Called after the user verifies their email (OTP or magic-link)
 * to finalise their profile before the account is activated.
 */
@Data
public class CompleteProfileRequest {
    private String email;
    /** Verification token returned by /email/verify-otp or /email/verify-magic-link */
    private String verificationToken;
    private String name;
    private String password;
    /** EMPLOYEE | MANAGER | HR_ADMIN */
    private String role;
}
