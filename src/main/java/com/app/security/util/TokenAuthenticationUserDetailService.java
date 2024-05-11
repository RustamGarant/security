package com.app.security.util;

import com.app.security.dto.Token;
import com.app.security.dto.TokenUser;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;

public class TokenAuthenticationUserDetailService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken) throws UsernameNotFoundException {

        if(authenticationToken.getPrincipal() instanceof Token token) {
            return new TokenUser(token.getSubject(), "nopassword", true, true,
                    token.getExpiresAt().isAfter(Instant.now()), true,
                    token.getAuthorities().stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList(),
                    token);
        }

        throw new UsernameNotFoundException("Principal must be RefreshToken.");
    }
}
