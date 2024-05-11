package com.app.security.config;

import com.app.security.dto.AccessToken;
import com.app.security.dto.RefreshToken;
import com.app.security.filter.RequestJwtTokensFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Objects;
import java.util.function.Function;

public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<RefreshToken, String> refreshTokenStringSerializer = Objects::toString;

    private Function<AccessToken, String> accessTokenStringSerializer = Objects::toString;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if(csrfConfigurer != null){
            csrfConfigurer.ignoringRequestMatchers(new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name()));
        }
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        RequestJwtTokensFilter filter = new RequestJwtTokensFilter();
        filter.setRefreshTokenStringSerializer(refreshTokenStringSerializer);
        filter.setAccessTokenStringSerializer(accessTokenStringSerializer);

        builder.addFilterAfter(filter, ExceptionTranslationFilter.class);
    }

    public JwtAuthenticationConfigurer refreshTokenSerializer(Function<RefreshToken, String> refreshTokenSerializer) {
        this.refreshTokenStringSerializer = refreshTokenSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenSerializer(Function<AccessToken, String> accessTokenSerializer) {
        this.accessTokenStringSerializer = accessTokenSerializer;
        return this;
    }
}
