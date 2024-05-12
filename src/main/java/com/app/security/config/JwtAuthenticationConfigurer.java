package com.app.security.config;

import com.app.security.dto.AccessToken;
import com.app.security.dto.RefreshToken;
import com.app.security.filter.RequestJwtTokensFilter;
import com.app.security.util.JwtAuthenticationConverter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Objects;
import java.util.function.Function;

@Builder
@Data
public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<RefreshToken, String> refreshTokenStringSerializer = Objects::toString;

    private Function<AccessToken, String> accessTokenStringSerializer = Objects::toString;

    private Function<String, AccessToken> accessTokenStringDeserializer;
    private Function<String, RefreshToken> refreshTokenStringDeserializer;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if(csrfConfigurer != null){
            csrfConfigurer.ignoringRequestMatchers(new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name()));
        }
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        RequestJwtTokensFilter requestJwtTokensFilter = new RequestJwtTokensFilter();
        requestJwtTokensFilter.setRefreshTokenStringSerializer(refreshTokenStringSerializer);
        requestJwtTokensFilter.setAccessTokenStringSerializer(accessTokenStringSerializer);

        var jwtAuthenticationFilter = new AuthenticationFilter(builder.getSharedObject(AuthenticationManager.class),
                new JwtAuthenticationConverter(accessTokenStringDeserializer, refreshTokenStringDeserializer));
        jwtAuthenticationFilter.setSuccessHandler(((request, response, authentication) ->
                CsrfFilter.skipRequest(request)));
        jwtAuthenticationFilter.setFailureHandler(((request, response, exception) ->
                response.sendError(HttpServletResponse.SC_FORBIDDEN)));

        builder.addFilterAfter(requestJwtTokensFilter, ExceptionTranslationFilter.class)
                .addFilterBefore(requestJwtTokensFilter, CsrfFilter.class);
    }
}
