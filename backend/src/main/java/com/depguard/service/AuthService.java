package com.depguard.service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-Memory Authentication & User Management Service.
 * Provides secure user registration, credential verification, and password reset.
 * Operates purely in-memory with zero external database dependencies.
 */
public class AuthService {

    public static class UserAccount {
        private String id;
        private String fullName;
        private String email;
        private String username;
        private String password;
        private String role;
        private String organization;
        private String createdAt;

        public UserAccount() {}

        public UserAccount(String id, String fullName, String email, String username, String password, String role, String organization) {
            this.id = id;
            this.fullName = fullName;
            this.email = email;
            this.username = username;
            this.password = password;
            this.role = role;
            this.organization = organization;
            this.createdAt = new Date().toString();
        }

        public String getId() { return id; }
        public String getFullName() { return fullName; }
        public String getEmail() { return email; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        public String getRole() { return role; }
        public String getOrganization() { return organization; }
        public String getCreatedAt() { return createdAt; }
    }

    private final Map<String, UserAccount> usersByUsername = new ConcurrentHashMap<>();
    private final Map<String, UserAccount> usersByEmail = new ConcurrentHashMap<>();

    public AuthService() {
        // Pre-seed standard authorized users
        seedDefaultAuthorizedUsers();
    }

    private void seedDefaultAuthorizedUsers() {
        // 1. Sanjay Natarajan (Lead DevSecOps Engineer)
        UserAccount sanjay = new UserAccount(
            UUID.randomUUID().toString(),
            "Sanjay Natarajan",
            "sanjay@depguard.io",
            "sanjay.natarajan",
            "depguard2026",
            "Lead DevSecOps Engineer",
            "DepGuard Security Intelligence"
        );
        registerInternal(sanjay);

        // 2. Administrator (SOC Operations Lead)
        UserAccount admin = new UserAccount(
            UUID.randomUUID().toString(),
            "SOC Administrator",
            "admin@depguard.io",
            "admin",
            "admin123",
            "SOC Operations Administrator",
            "Global Cybersecurity Center"
        );
        registerInternal(admin);
    }

    private void registerInternal(UserAccount user) {
        usersByUsername.put(user.getUsername().toLowerCase(), user);
        usersByEmail.put(user.getEmail().toLowerCase(), user);
    }

    /**
     * Authenticates an authorized user by username or email and password.
     */
    public UserAccount authenticate(String identifier, String password) {
        if (identifier == null || password == null) return null;
        String cleanId = identifier.trim().toLowerCase();

        UserAccount user = usersByUsername.get(cleanId);
        if (user == null) {
            user = usersByEmail.get(cleanId);
        }

        if (user != null && user.getPassword().equals(password.trim())) {
            return user;
        }
        return null;
    }

    /**
     * Registers a new authorized user.
     */
    public synchronized String register(String fullName, String email, String username, String password, String role, String organization) {
        if (fullName == null || fullName.trim().isEmpty()) return "Full name is required.";
        if (email == null || !email.contains("@")) return "A valid work email address is required.";
        if (username == null || username.trim().length() < 3) return "Username must be at least 3 characters long.";
        if (password == null || password.trim().length() < 6) return "Password must be at least 6 characters long.";

        String uKey = username.trim().toLowerCase();
        String eKey = email.trim().toLowerCase();

        if (usersByUsername.containsKey(uKey)) {
            return "Username is already registered. Please choose another username or log in.";
        }
        if (usersByEmail.containsKey(eKey)) {
            return "Email is already registered. Please log in or reset your password.";
        }

        UserAccount newUser = new UserAccount(
            UUID.randomUUID().toString(),
            fullName.trim(),
            eKey,
            uKey,
            password.trim(),
            (role != null && !role.trim().isEmpty()) ? role.trim() : "Security Analyst",
            (organization != null && !organization.trim().isEmpty()) ? organization.trim() : "Independent Security Auditor"
        );

        registerInternal(newUser);
        return null; // Success (no error)
    }

    /**
     * Resets the password for an existing registered user.
     */
    public synchronized String resetPassword(String identifier, String newPassword) {
        if (identifier == null || identifier.trim().isEmpty()) return "Username or Email is required.";
        if (newPassword == null || newPassword.trim().length() < 6) return "New password must be at least 6 characters.";

        String cleanId = identifier.trim().toLowerCase();
        UserAccount user = usersByUsername.get(cleanId);
        if (user == null) {
            user = usersByEmail.get(cleanId);
        }

        if (user == null) {
            return "No authorized user found with that Username or Email ID.";
        }

        user.setPassword(newPassword.trim());
        return null; // Success
    }

    public boolean isUserExists(String identifier) {
        if (identifier == null) return false;
        String cleanId = identifier.trim().toLowerCase();
        return usersByUsername.containsKey(cleanId) || usersByEmail.containsKey(cleanId);
    }
}
