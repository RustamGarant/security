package com.app.security.config;

import com.app.security.dto.*;
import jakarta.servlet.http.*;
import java.time.*;
import java.time.temporal.*;
import java.util.*;
import java.util.function.*;
import lombok.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.web.authentication.session.*;

@Setter
public class TokenCookieSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

    private Function<Authentication, Token> tokenCookieFactory = new DefaultTokenCookieFactory();
    private Function<Token, String> tokenStringSerializer = Objects::toString;

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
        HttpServletResponse response) throws SessionAuthenticationException {
        if(authentication instanceof UsernamePasswordAuthenticationToken){
            var token = tokenCookieFactory.apply(authentication);
            var tokenString = tokenStringSerializer.apply(token);

            var cookie = new Cookie("__Host-auth-token", tokenString);
            cookie.setPath("/");
            cookie.setDomain(null);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setMaxAge((int) ChronoUnit.SECONDS.between(Instant.now(), token.getExpiresAt()));

            response.addCookie(cookie);
        }
    }
}
