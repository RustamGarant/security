package com.app.security.dto;

public record Tokens(
        String accessToken, String accessTokenExpiry,
        String refreshToken, String refreshTokenExpiry
) {
}
