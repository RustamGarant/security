package com.app.security.config;

import com.app.security.filter.*;
import com.app.security.service.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.*;
import org.springframework.security.config.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.http.*;
import org.springframework.security.core.authority.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.*;
import org.springframework.security.web.access.*;
import org.springframework.security.web.csrf.*;

@Configuration
public class SecurityConfig {

    @Bean
    public TokenCookieJweStringSerializer tokenCookieJweStringSerializer(
        @Value("${jwt.cookie-token-key}") String cookieTokenKey
    ) throws Exception {
        return new TokenCookieJweStringSerializer(new DirectEncrypter(
            OctetSequenceKey.parse(cookieTokenKey)
        ));
    }

    @Bean
    public TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer(
        @Value("${jwt.cookie-token-key}") String cookieTokenKey,
        JdbcTemplate jdbcTemplate
    ) throws Exception {
        return TokenCookieAuthenticationConfigurer.builder()
            .tokenCookieStringDeserializer(new TokenCookieJweStringDeserializer(
                new DirectDecrypter(
                    OctetSequenceKey.parse(cookieTokenKey)
                )
            ))
            .jdbcTemplate(jdbcTemplate)
            .build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer,
        TokenCookieJweStringSerializer tokenCookieJweStringSerializer) throws Exception {

        var tokenCookieSessionAuthenticationStrategy = new TokenCookieSessionAuthenticationStrategy();
        tokenCookieSessionAuthenticationStrategy.setTokenStringSerializer(tokenCookieJweStringSerializer);

        http.httpBasic(Customizer.withDefaults())
            .formLogin(Customizer.withDefaults())
            .addFilterAfter(new GetCsrfTokenFilter(), ExceptionTranslationFilter.class)
            .authorizeHttpRequests(authorizeHttpRequests ->
                authorizeHttpRequests
                    .requestMatchers("/manager.html", "/manager").hasRole("MANAGER")
                    .requestMatchers("/error", "index.html").permitAll()
                    .anyRequest().authenticated())
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionAuthenticationStrategy(tokenCookieSessionAuthenticationStrategy))
            .csrf(csrf -> csrf.csrfTokenRepository(new CookieCsrfTokenRepository())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                .sessionAuthenticationStrategy(((authentication, request, response) -> {})));

        http.apply(tokenCookieAuthenticationConfigurer);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        return username -> jdbcTemplate.query("select * from t_user where c_username = ?",
            (rs, i) -> User.builder()
                .username(rs.getString("c_username"))
                .password(rs.getString("c_password"))
                .authorities(
                    jdbcTemplate.query("select c_authority from t_user_authority where id_user = ?",
                        (rs1, i1) ->
                            new SimpleGrantedAuthority(rs1.getString("c_authority")),
                        rs.getInt("id")))
                .build(), username).stream().findFirst().orElse(null);
    }
}
