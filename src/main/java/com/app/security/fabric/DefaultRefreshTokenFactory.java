package com.app.security.fabric;

import com.app.security.dto.RefreshToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.UUID;
import java.util.function.Function;

@Component
public class DefaultRefreshTokenFactory implements Function<Authentication, RefreshToken> {

    @Value("${security.jwt.refresh-token.ttl-days}")
    private int ttl;
    private Duration tokenTTL = Duration.ofDays(ttl);

    /**
     * Take customer authorities form Spring Security
     * Convert them by adding prefix "GRANT_" because refresh token need to transfer them without using
     * Add own authorities required for REFRESH TOKEN
     *
     * @param authentication the function argument
     * @return
     */
    @Override
    public RefreshToken apply(Authentication authentication) {
        var authorities = new LinkedList<String>();
        authorities.add("JWT_REFRESH");
        authorities.add("JWT_LOGOUT");
        authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> "GRANT_" + authority)
                .forEach(authorities::add);

        Instant now = Instant.now();
        return new RefreshToken(
                UUID.randomUUID(),
                authentication.getName(),
                authorities,
                now,
                now.plus(this.tokenTTL));
    }
}
