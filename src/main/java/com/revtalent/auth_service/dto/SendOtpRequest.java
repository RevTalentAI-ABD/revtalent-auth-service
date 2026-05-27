package com.revtalent.auth_service.dto;

import lombok.Data;

@Data
public class SendOtpRequest {
    private String email;
    /** "login" or "register" */
    private String type;
}
