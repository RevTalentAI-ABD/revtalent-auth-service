package com.revtalent.auth_service.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String name;
    private String username;
    private String email;
    private String password;
    private String role;
    private String department;
}