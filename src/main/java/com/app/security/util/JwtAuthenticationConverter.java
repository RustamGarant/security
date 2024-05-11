package com.app.security.util;

import com.app.security.dto.AccessToken;
import com.app.security.dto.RefreshToken;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.function.Function;

@RequiredArgsConstructor
public class JwtAuthenticationConverter implements AuthenticationConverter {

    private final Function<String, AccessToken> accessTokenStringDeserializer;
    private final Function<String, RefreshToken> refreshTokenStringDeserializer;

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authorization != null && authorization.startsWith("Bearer ")){
            var token = authorization.replace("Bearer ", "");
            var accessToken = accessTokenStringDeserializer.apply(token);
            if(accessToken != null){
                return new PreAuthenticatedAuthenticationToken(accessToken, token);
            }
            var refreshToken = refreshTokenStringDeserializer.apply(token);
            if(refreshToken != null){
                return new PreAuthenticatedAuthenticationToken(refreshToken, token);
            }
        }

        return null;
    }
}
