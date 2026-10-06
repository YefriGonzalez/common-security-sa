package com.sa.common_security.dto;

public record JwtAuthenticatedUser(
        Long userId,
        Long profileId,
        String username) {
}