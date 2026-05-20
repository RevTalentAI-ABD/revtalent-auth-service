package com.revtalent.auth_service.dto;

import lombok.*;

@Data
public class ChangePasswordDTO {
    private String currentPassword;
    private String newPassword;
}
