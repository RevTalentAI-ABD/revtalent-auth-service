package com.revtalent.auth_service.dto;

import lombok.Data;

@Data
public class VerifyOtpRequest {
    private String email;
    private String otp;
    /** "login" or "register" */
    private String type;
}
