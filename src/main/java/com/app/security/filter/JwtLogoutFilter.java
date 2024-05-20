package com.app.security.filter;

import com.app.security.dto.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.*;
import lombok.*;
import org.springframework.jdbc.core.*;
import org.springframework.security.access.*;
import org.springframework.security.core.authority.*;
import org.springframework.security.web.authentication.preauth.*;
import org.springframework.security.web.context.*;
import org.springframework.security.web.util.matcher.*;
import org.springframework.web.filter.*;

@RequiredArgsConstructor
@Setter
public class JwtLogoutFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/logout");
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private final JdbcTemplate jdbcTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        if (requestMatcher.matches(request)) {
            if (securityContextRepository.containsContext(request)) {
                var context = securityContextRepository.loadDeferredContext(request).get();
                if (context != null
                    && context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken
                    &&
                    context.getAuthentication().getPrincipal() instanceof TokenUser user &&
                    context.getAuthentication().getAuthorities()
                        .contains(new SimpleGrantedAuthority("JWT_LOGOUT"))) {
                    this.jdbcTemplate.update(
                        "insert into t_deactivated_token (id, c_keep_until) values (?, ?)",
                        user.getToken().getId(), Date.from(user.getToken().getExpiresAt()));
                    response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated with JWT");
        }
        filterChain.doFilter(request, response);
    }
}
