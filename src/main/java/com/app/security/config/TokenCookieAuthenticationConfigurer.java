package com.app.security.config;

import com.app.security.dto.*;
import com.app.security.service.*;
import jakarta.servlet.http.*;
import java.util.*;
import java.util.function.*;
import lombok.*;
import org.springframework.jdbc.core.*;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.*;
import org.springframework.security.web.authentication.preauth.*;
import org.springframework.security.web.csrf.*;

@Setter
@Builder
public class TokenCookieAuthenticationConfigurer
    extends AbstractHttpConfigurer<TokenCookieAuthenticationConfigurer, HttpSecurity> {

    private Function<String, Token> tokenCookieStringDeserializer;

    private JdbcTemplate jdbcTemplate;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.logout(logout -> logout.addLogoutHandler(
                new CookieClearingLogoutHandler("__Host-auth-token"))
            .addLogoutHandler((request, response, authentication) -> {
                if (authentication != null &&
                    authentication.getPrincipal() instanceof TokenUser user) {
                    this.jdbcTemplate.update("insert into t_deactivated_token (id, c_keep_until) values (?, ?)",
                        user.getToken().getId(), Date.from(user.getToken().getExpiresAt()));

                    response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                }
            }));
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        var cookieAuthenticationFilter = new AuthenticationFilter(
            builder.getSharedObject(AuthenticationManager.class),
            new TokenCookieAuthenticationConverter(this.tokenCookieStringDeserializer));
        cookieAuthenticationFilter.setSuccessHandler((request, response, authentication) -> {});
        cookieAuthenticationFilter.setFailureHandler(
            new AuthenticationEntryPointFailureHandler(
                new Http403ForbiddenEntryPoint()
            )
        );

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(
            new TokenAuthenticationUserDetailsService(this.jdbcTemplate));

        builder.addFilterAfter(cookieAuthenticationFilter, CsrfFilter.class)
            .authenticationProvider(authenticationProvider);
    }

}
