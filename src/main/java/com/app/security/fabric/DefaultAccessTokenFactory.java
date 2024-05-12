package com.app.security.fabric;

import com.app.security.dto.AccessToken;
import com.app.security.dto.RefreshToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class DefaultAccessTokenFactory implements Function<RefreshToken, AccessToken> {

    @Value("${security.jwt.access-token.ttl-minutes}")
    private int ttl;
    private Duration tokenTTL = Duration.ofDays(ttl);

    /**
     * Generate access token from refresh
     * Take customer authorities from refresh token marked "GRANT_"
     * @param refreshToken the function argument
     * @return
     */
    @Override
    public AccessToken apply(RefreshToken refreshToken) {
        Instant now = Instant.now();

        return new AccessToken(
                refreshToken.id,
                refreshToken.subject,
                refreshToken.authorities.stream()
                        .filter(auth -> auth.startsWith("GRANT_"))
                        .map(auth -> auth.substring(6))
                        .collect(Collectors.toList()),
                now,
                now.plus(tokenTTL)
        );
    }
}
