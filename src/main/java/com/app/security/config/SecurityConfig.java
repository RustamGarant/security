package com.app.security.config;

import com.app.security.filter.*;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.*;
import org.springframework.security.config.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.http.*;
import org.springframework.security.core.authority.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.web.*;
import org.springframework.security.web.access.*;

@Configuration
public class SecurityConfig {

    @Bean
    public TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer()
        throws Exception {
        return new TokenCookieAuthenticationConfigurer();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        TokenCookieAuthenticationConfigurer tokenCookieAuthenticationConfigurer) throws Exception {

        http.httpBasic(Customizer.withDefaults())
            .addFilterAfter(new GetCsrfTokenFilter(), ExceptionTranslationFilter.class)
            .authorizeHttpRequests(authorizeHttpRequests ->
                authorizeHttpRequests
                    .requestMatchers("/manager.html", "/manager").hasRole("MANAGER")
                    .requestMatchers("/error", "index.html").permitAll()
                    .anyRequest().authenticated())
            .sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

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
