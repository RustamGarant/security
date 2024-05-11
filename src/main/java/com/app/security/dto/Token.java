package com.app.security.dto;

import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
public abstract class Token {
    UUID id;
    String subject;
    List<String> authorities;
    Instant createdAt;
    Instant expiresAt;

}
