package com.app.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@AllArgsConstructor
public class Token {
    public UUID id;
    public String subject;
    public List<String> authorities;
    public Instant createdAt;
    public Instant expiresAt;

}
