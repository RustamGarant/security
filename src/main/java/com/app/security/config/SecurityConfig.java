package com.app.security.config;

import com.app.security.util.AccessTokenJwsStringSerializer;
import com.app.security.util.RefreshTokenJweStringSerializer;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.text.ParseException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public JwtAuthenticationConfigurer jwtAuthenticationConfigurer(
            @Value("${security.jwt.refresh-token.key}") String refreshTokenKey,
            @Value("${security.jwt.access-token.key}") String accessTokenKey
    ) throws ParseException, KeyLengthException {
        return new JwtAuthenticationConfigurer()
                .accessTokenSerializer(new AccessTokenJwsStringSerializer(
                        new MACSigner(OctetSequenceKey.parse(accessTokenKey))
                ))
                .refreshTokenSerializer(new RefreshTokenJweStringSerializer(
                        new DirectEncrypter(OctetSequenceKey.parse(refreshTokenKey))
                ));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationConfigurer jwtAuthenticationConfigurer) throws Exception {
        http.apply(jwtAuthenticationConfigurer);

        return http
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeHttpRequests ->
                                authorizeHttpRequests
                                        .requestMatchers("/manager.html").hasRole("MANAGER")
                                        .requestMatchers("/error").permitAll()
                                        .anyRequest().authenticated())
                .build();
    }

}
