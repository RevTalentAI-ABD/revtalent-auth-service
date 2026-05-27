package com.revtalent.auth_service.service;

import com.revtalent.auth_service.dto.CompleteProfileRequest;
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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final OtpService otpService;

    private final Map<String, Integer>       failedLoginAttempts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lockedAccounts      = new ConcurrentHashMap<>();

    // Verification tokens issued after OTP/magic-link verified, consumed by /register/complete
    private final Map<String, String> pendingVerifications = new ConcurrentHashMap<>();

    private static final int MAX_FAILED_ATTEMPTS        = 5;
    private static final int LOCK_TIME_DURATION_MINUTES = 15;

    // ── Password Login ────────────────────────────────────────────────────────

    public Map<String, String> login(LoginRequest req) {
        if (req.getUsername() == null || req.getUsername().isBlank()) {
            throw new RuntimeException("Username is required");
        }
        if (req.getPassword() == null || req.getPassword().isBlank()) {
            throw new RuntimeException("Password is required");
        }
        String key = req.getUsername().toLowerCase();

        LocalDateTime lockTime = lockedAccounts.get(key);
        if (lockTime != null) {
            if (lockTime.plusMinutes(LOCK_TIME_DURATION_MINUTES).isAfter(LocalDateTime.now())) {
                throw new RuntimeException(
                        "Account is locked due to too many failed attempts. Please try again later.");
            } else {
                lockedAccounts.remove(key);
                failedLoginAttempts.remove(key);
            }
        }

        Users user;
        try {
            user = userRepo.findByUsername(key)
                    .or(() -> userRepo.findByEmail(key))
                    .orElseThrow(() -> new RuntimeException("Invalid credentials"));
        } catch (RuntimeException e) {
            recordFailedAttempt(key);
            throw e;
        }

        if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            recordFailedAttempt(key);
            throw new RuntimeException("Invalid credentials");
        }

        if (!user.isActive()) {
            throw new RuntimeException("Account is inactive. Please verify OTP.");
        }

        failedLoginAttempts.remove(key);
        lockedAccounts.remove(key);

        return buildAuthResponse(user);
    }

    private void recordFailedAttempt(String key) {
        int attempts = failedLoginAttempts.getOrDefault(key, 0) + 1;
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            lockedAccounts.put(key, LocalDateTime.now());
            failedLoginAttempts.remove(key);
        } else {
            failedLoginAttempts.put(key, attempts);
        }
    }

    // ── Email / OTP Login ─────────────────────────────────────────────────────

    /**
     * POST /api/auth/email/send-otp
     * Sends a 6-digit OTP. type = "login" | "register".
     */
    public void sendOtp(String email, String type) {
        if (email == null || email.isBlank()) throw new RuntimeException("Email is required");
        String normalised = email.toLowerCase();
        String otpType    = (type != null && !type.isBlank()) ? type.toLowerCase() : "login";

        if ("login".equals(otpType)) {
            // For login, account must already exist
            userRepo.findByEmail(normalised)
                    .orElseThrow(() -> new RuntimeException(
                            "Account not found. Please register first."));
        } else if ("register".equals(otpType)) {
            // For register, email must not already be active
            userRepo.findByEmail(normalised).ifPresent(u -> {
                if (u.isActive()) throw new RuntimeException("Email already registered.");
            });
        }

        otpService.generateAndSendTypedOtp(normalised, otpType);
    }

    /**
     * POST /api/auth/email/verify-otp
     * For type="login": verifies OTP and returns JWT.
     * For type="register": verifies OTP and returns a short-lived verification token
     *   that /register/complete must consume.
     */
    @Transactional
    public Map<String, String> verifyEmailOtp(String email, String otp, String type) {
        if (email == null || email.isBlank() || otp == null || otp.isBlank()) {
            throw new RuntimeException("Email and OTP are required");
        }
        String normalised = email.toLowerCase();
        String otpType    = (type != null && !type.isBlank()) ? type.toLowerCase() : "login";

        boolean valid = otpService.verifyTypedOtp(normalised, otp, otpType);
        if (!valid) throw new RuntimeException("Invalid or expired OTP");

        if ("register".equals(otpType)) {
            // Issue a short-lived verification token; no account exists yet
            String verificationToken = UUID.randomUUID().toString().replace("-", "");
            pendingVerifications.put(normalised, verificationToken);
            Map<String, String> res = new HashMap<>();
            res.put("verificationToken", verificationToken);
            res.put("message", "Email verified. Complete your profile to finish registration.");
            return res;
        }

        // "login" flow — activate and log in
        Users user = userRepo.findByEmail(normalised)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        if (!user.isActive()) {
            user.setActive(true);
            userRepo.save(user);
        }
        return buildAuthResponse(user);
    }

    // ── Magic Link ────────────────────────────────────────────────────────────

    /**
     * POST /api/auth/email/send-magic-link
     * type = "login" | "register"
     */
    public void sendMagicLink(String email, String type) {
        if (email == null || email.isBlank()) throw new RuntimeException("Email is required");
        String normalised = email.toLowerCase();
        String mlType     = (type != null && !type.isBlank()) ? type.toLowerCase() : "login";

        if ("login".equals(mlType)) {
            userRepo.findByEmail(normalised)
                    .orElseThrow(() -> new RuntimeException(
                            "Account not found. Please register first."));
        } else if ("register".equals(mlType)) {
            userRepo.findByEmail(normalised).ifPresent(u -> {
                if (u.isActive()) throw new RuntimeException("Email already registered.");
            });
        }

        otpService.generateAndSendTypedMagicLink(normalised, mlType);
    }

    /**
     * POST /api/auth/magic-link-verify  (existing — kept for backwards-compat)
     * POST /api/auth/email/verify-magic-link  (new alias)
     */
    @Transactional
    public Map<String, String> verifyMagicLink(String email, String token) {
        if (email == null || email.isBlank() || token == null || token.isBlank()) {
            throw new RuntimeException("Email and token are required");
        }
        String normalised = email.toLowerCase();

        // Try login magic-link first, then register magic-link
        boolean verified = false;
        String  matchedType = null;

        if (otpService.verifyTypedOtp(normalised, token, "magic-login")) {
            verified = true; matchedType = "login";
        } else if (otpService.verifyTypedOtp(normalised, token, "magic-register")) {
            verified = true; matchedType = "register";
        }

        if (!verified) throw new RuntimeException("Invalid or expired Magic Link");

        if ("register".equals(matchedType)) {
            String verificationToken = UUID.randomUUID().toString().replace("-", "");
            pendingVerifications.put(normalised, verificationToken);
            Map<String, String> res = new HashMap<>();
            res.put("verificationToken", verificationToken);
            res.put("message", "Email verified. Complete your profile to finish registration.");
            return res;
        }

        // Login flow
        Users user = userRepo.findByEmail(normalised)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        if (!user.isActive()) {
            user.setActive(true);
            userRepo.save(user);
        }
        return buildAuthResponse(user);
    }

    // ── Complete Profile (step 3 of registration) ─────────────────────────────

    /**
     * POST /api/auth/register/complete
     * Consumes the verificationToken issued by verify-otp/verify-magic-link
     * and creates (or completes) the user account.
     */
    @Transactional
    public Map<String, String> completeProfile(CompleteProfileRequest req) {
        if (req.getEmail() == null || req.getEmail().isBlank())
            throw new RuntimeException("Email is required");
        if (req.getVerificationToken() == null || req.getVerificationToken().isBlank())
            throw new RuntimeException("Verification token is required");
        if (req.getName() == null || req.getName().isBlank())
            throw new RuntimeException("Name is required");
        if (req.getPassword() == null || req.getPassword().length() < 8)
            throw new RuntimeException("Password must be at least 8 characters");

        String normalised = req.getEmail().toLowerCase();
        String expected   = pendingVerifications.get(normalised);
        if (expected == null || !expected.equals(req.getVerificationToken())) {
            throw new RuntimeException("Invalid or expired verification token. Please restart registration.");
        }

        pendingVerifications.remove(normalised);

        String roleStr = req.getRole() != null
                ? req.getRole().toUpperCase().trim()
                         .replace("HRADMIN", "HR_ADMIN")
                         .replace("HR ADMIN", "HR_ADMIN")
                : "EMPLOYEE";

        Users.Role role;
        try {
            role = Users.Role.valueOf(roleStr);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid role: " + roleStr);
        }
        if (role == Users.Role.HR_ADMIN) {
            throw new RuntimeException(
                    "HR Admin accounts must be provisioned by an existing administrator");
        }

        // Upsert: if a pending (inactive) user already exists, update it; otherwise create new
        Users user = userRepo.findByEmail(normalised).orElseGet(Users::new);
        if (user.isActive()) {
            throw new RuntimeException("An active account already exists for this email.");
        }

        String username = normalised.split("@")[0]
                + "_" + UUID.randomUUID().toString().substring(0, 4);

        user.setName(req.getName());
        user.setEmail(normalised);
        if (user.getUsername() == null) user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setRole(role);
        user.setActive(true);

        Users saved = userRepo.save(user);
        return buildAuthResponse(saved);
    }

    // ── Register (legacy — password-first flow) ────────────────────────────────

    @Transactional
    public UserResponse register(RegisterRequest req) {
        if (req.getUsername() == null || req.getUsername().isBlank())
            throw new RuntimeException("Username is required");
        if (req.getEmail() == null || req.getEmail().isBlank())
            throw new RuntimeException("Email is required");
        if (req.getPassword() == null || req.getPassword().isBlank())
            throw new RuntimeException("Password is required");

        userRepo.findByUsername(req.getUsername().toLowerCase())
                .ifPresent(u -> { throw new RuntimeException("Username already exists"); });
        userRepo.findByEmail(req.getEmail().toLowerCase())
                .ifPresent(u -> { throw new RuntimeException("Email already exists"); });

        String roleStr = req.getRole() != null
                ? req.getRole().toUpperCase().trim()
                        .replace("HRADMIN", "HR_ADMIN")
                        .replace("HR ADMIN", "HR_ADMIN")
                : "EMPLOYEE";
        Users.Role role;
        try {
            role = Users.Role.valueOf(roleStr);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid role: " + roleStr);
        }
        if (role == Users.Role.HR_ADMIN)
            throw new RuntimeException(
                    "HR Admin accounts must be provisioned by an existing administrator");

        Users user = new Users();
        user.setName(req.getName());
        user.setUsername(req.getUsername().toLowerCase());
        user.setEmail(req.getEmail().toLowerCase());
        user.setPasswordHash(passwordEncoder.encode(req.getPassword()));
        user.setRole(role);
        user.setActive(false);
        user.setDepartment(req.getDepartment());

        Users saved = userRepo.save(user);
        otpService.generateAndSendTypedOtp(saved.getEmail(), "register");

        return UserResponse.builder()
                .id(saved.getId())
                .name(saved.getName())
                .username(saved.getUsername())
                .email(saved.getEmail())
                .role(saved.getRole().name())
                .build();
    }

    // ── OTP Verification (legacy endpoint) ────────────────────────────────────

    public Map<String, String> verifyOtp(String email, String otp) {
        boolean valid = otpService.verifyOtp(email.toLowerCase(), otp);
        if (!valid) throw new RuntimeException("Invalid or expired OTP");

        Users user = userRepo.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new RuntimeException("No account found"));
        user.setActive(true);
        userRepo.save(user);

        Map<String, String> res = new HashMap<>();
        res.put("message", "Email verified successfully. Please login.");
        return res;
    }

    // ── Forgot Password ───────────────────────────────────────────────────────

    /**
     * POST /api/auth/forgot-password
     * Sends a password-reset link via email. Silently succeeds if email not found
     * to prevent enumeration.
     */
    public void forgotPassword(String email) {
        if (email == null || email.isBlank()) throw new RuntimeException("Email is required");
        // Prevent enumeration — only send if account exists
        userRepo.findByEmail(email.toLowerCase())
                .ifPresent(u -> otpService.generateAndSendTypedOtp(email.toLowerCase(), "forgot-password"));
    }

    /**
     * POST /api/auth/verify-email  (legacy — triggers OTP for forgot-password flow)
     */
    public void verifyEmail(String email) {
        userRepo.findByEmail(email.toLowerCase())
                .ifPresent(u -> otpService.generateAndSendTypedOtp(
                        email.toLowerCase(), "forgot-password"));
    }

    // ── Reset Password ────────────────────────────────────────────────────────

    @Transactional
    public void resetPassword(String email, String otp, String newPassword) {
        String normalised = email.toLowerCase();
        // Accept both OTP-style and token-style resets
        boolean valid = otpService.verifyTypedOtp(normalised, otp, "forgot-password");
        if (!valid) throw new RuntimeException("Invalid or expired OTP");

        Users user = userRepo.findByEmail(normalised)
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));
        if (newPassword == null || newPassword.length() < 8)
            throw new RuntimeException("Password must be at least 8 characters");

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setActive(true);
        userRepo.save(user);
    }

    // ── Get User ──────────────────────────────────────────────────────────────

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

    // ── Auth response builder ─────────────────────────────────────────────────

    private Map<String, String> buildAuthResponse(Users user) {
        String token = jwtUtil.generateToken(user.getUsername(), user.getRole().name(), user.getId());
        Map<String, String> res = new HashMap<>();
        res.put("token", token);
        res.put("role",  user.getRole().name());
        res.put("name",  user.getName());
        res.put("email", user.getEmail());
        res.put("id",    user.getId().toString());
        return res;
    }
}
