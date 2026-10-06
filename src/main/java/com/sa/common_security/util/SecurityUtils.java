package com.sa.common_security.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.sa.common_security.dto.JwtAuthenticatedUser;

public final class SecurityUtils {

    private SecurityUtils() {
    }

    public static Authentication getAuthentication() {

        return SecurityContextHolder
                .getContext()
                .getAuthentication();
    }

    public static JwtAuthenticatedUser getCurrentUser() {

        Authentication authentication = getAuthentication();

        if (authentication == null) {
            return null;
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof JwtAuthenticatedUser user) {
            return user;
        }

        return null;
    }

    public static Long getCurrentUserId() {

        JwtAuthenticatedUser user = getCurrentUser();

        return user != null
                ? user.userId()
                : null;
    }

    public static Long getCurrentProfileId() {

        JwtAuthenticatedUser user = getCurrentUser();

        return user != null
                ? user.profileId()
                : null;
    }

    public static String getCurrentUsername() {

        JwtAuthenticatedUser user = getCurrentUser();

        return user != null
                ? user.username()
                : null;
    }

    public static boolean hasRole(String role) {

        Authentication authentication = getAuthentication();

        if (authentication == null) {
            return false;
        }

        return authentication
                .getAuthorities()
                .stream()
                .anyMatch(authority -> authority
                        .getAuthority()
                        .equals(role));
    }

    public static boolean isAuthenticated() {

        Authentication authentication = getAuthentication();

        return authentication != null
                && authentication.isAuthenticated();
    }
}