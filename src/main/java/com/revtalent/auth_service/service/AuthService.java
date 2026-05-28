package com.revtalent.auth_service.service;

import com.revtalent.auth_service.dto.LoginRequest;
import com.revtalent.auth_service.dto.RegisterRequest;
import com.revtalent.auth_service.dto.UserResponse;
import com.revtalent.auth_service.model.Users;
import com.revtalent.auth_service.repository.UserRepository;
import com.revtalent.auth_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final OtpService otpService;

    // ── Login ─────────────────────────────────────────────────────────────────
    public Map<String, String> login(LoginRequest req) {
        Users user = userRepo.findByUsername(req.getUsername().toLowerCase())
                .or(() -> userRepo.findByEmail(req.getUsername().toLowerCase()))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole().name());

        Map<String, String> res = new HashMap<>();
        res.put("token", token);
        res.put("role",  user.getRole().name());
        res.put("name",  user.getName());
        res.put("email", user.getEmail());
        res.put("id",    user.getId().toString());
        return res;
    }

    // ── Register ──────────────────────────────────────────────────────────────
    @Transactional
    public UserResponse register(RegisterRequest req) {
        userRepo.findByUsername(req.getUsername().toLowerCase())
                .ifPresent(u -> { throw new RuntimeException("Username already exists"); });

        String roleStr = req.getRole()
                .toUpperCase().trim()
                .replace("HRADMIN", "HR_ADMIN")
                .replace("HR ADMIN", "HR_ADMIN");
        Users.Role role = Users.Role.valueOf(roleStr);

        Users user = new Users();
        user.setName(req.getName());
        user.setUsername(req.getUsername().toLowerCase());
        user.setEmail(req.getEmail().toLowerCase());
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setRole(role);
        user.setActive(true);
        user.setDepartment(req.getDepartment());

        Users saved = userRepo.save(user);

        // Send OTP for email verification
        otpService.generateAndSendOtp(saved.getEmail());

        return UserResponse.builder()
                .id(saved.getId())
                .name(saved.getName())
                .username(saved.getUsername())
                .email(saved.getEmail())
                .role(saved.getRole().name())
                .build();
    }

    // ── OTP Verification ──────────────────────────────────────────────────────
    public Map<String, String> verifyOtp(String email, String otp) {
        boolean valid = otpService.verifyOtp(email, otp);
        if (!valid) throw new RuntimeException("Invalid or expired OTP");
        Map<String, String> res = new HashMap<>();
        res.put("message", "Email verified successfully. Please login.");
        return res;
    }

    // ── Forgot Password ───────────────────────────────────────────────────────
    public void verifyEmail(String email) {
        userRepo.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new RuntimeException("No account found with this email"));
        otpService.generateAndSendOtp(email.toLowerCase());
    }

    // ── Reset Password ────────────────────────────────────────────────────────
    @Transactional
    public void resetPassword(String email, String newPassword) {
        Users user = userRepo.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new RuntimeException("No account found with this email"));
        if (newPassword == null || newPassword.length() < 8)
            throw new RuntimeException("Password must be at least 8 characters");
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepo.save(user);
    }

    // ── Get User by Username ──────────────────────────────────────────────────
    public UserResponse getUserByUsername(String username) {
        Users user = userRepo.findByUsername(username.toLowerCase())
                .orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }
}