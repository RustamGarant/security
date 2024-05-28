package com.app.security.config;

import com.app.security.dto.*;

import java.time.*;
import java.util.*;
import java.util.function.*;

import lombok.*;
import org.springframework.security.core.*;

@Setter
public class DefaultTokenCookieFactory implements Function<Authentication, Token> {

    private Duration tokenTtl = Duration.ofDays(1);

    @Override
    public Token apply(Authentication authentication) {
        var now = Instant.now();
        return new Token(UUID.randomUUID(), authentication.getName(),
                authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList(),
                now,
                now.plus(this.tokenTtl));
    }
}
