package com.app.security.service;

import com.app.security.dto.*;
import java.time.*;
import lombok.*;
import org.springframework.jdbc.core.*;
import org.springframework.security.core.authority.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.authentication.preauth.*;

@RequiredArgsConstructor
public class TokenAuthenticationUserDetailService implements
    AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken)
        throws UsernameNotFoundException {

        if (authenticationToken.getPrincipal() instanceof Token token) {
            return new TokenUser(token.getSubject(), "nopassword", true, true,
                !jdbcTemplate.queryForObject("""
                    select exists(select id from t_deactivated_token where id = ?)
                    """, Boolean.class, token.getId()) &&
                    token.getExpiresAt().isAfter(Instant.now()),
                true,
                token.getAuthorities().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList(),
                token);
        }

        throw new UsernameNotFoundException("Principal must be RefreshToken.");
    }
}
