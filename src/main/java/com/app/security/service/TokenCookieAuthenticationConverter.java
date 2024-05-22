package com.app.security.service;

import com.app.security.dto.*;
import jakarta.servlet.http.*;
import java.util.function.*;
import java.util.stream.*;
import org.springframework.security.core.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.preauth.*;

public class TokenCookieAuthenticationConverter implements AuthenticationConverter {

    private final Function<String, Token> tokenCookieStringDeserializer;

    public TokenCookieAuthenticationConverter(Function<String, Token> tokenCookieStringDeserializer) {
        this.tokenCookieStringDeserializer = tokenCookieStringDeserializer;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (request.getCookies() != null) {
            return Stream.of(request.getCookies())
                .filter(cookie -> cookie.getName().equals("__Host-auth-token"))
                .findFirst()
                .map(cookie -> {
                    var token = this.tokenCookieStringDeserializer.apply(cookie.getValue());
                    return new PreAuthenticatedAuthenticationToken(token, cookie.getValue());
                })
                .orElse(null);
        }

        return null;
    }
}
