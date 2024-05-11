package com.app.security.filter;

import com.app.security.dto.AccessToken;
import com.app.security.dto.RefreshToken;
import com.app.security.dto.Tokens;
import com.app.security.fabric.DefaultAccessTokenFactory;
import com.app.security.fabric.DefaultRefreshTokenFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.Setter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.Objects;
import java.util.function.Function;


public class RequestJwtTokensFilter extends OncePerRequestFilter {

    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("jwt/tokens", HttpMethod.POST.name());

    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final Function<Authentication, RefreshToken> refreshTokenFactory = new DefaultRefreshTokenFactory();

    private final Function<RefreshToken, AccessToken> accessTokenFactory = new DefaultAccessTokenFactory();

    @Setter
    private Function<RefreshToken, String> refreshTokenStringSerializer = Objects::toString;

    @Setter
    private Function<AccessToken, String> accessTokenStringSerializer = Objects::toString;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        if(this.requestMatcher.matches(request)){
            if(this.securityContextRepository.containsContext(request)) {
                var context = this.securityContextRepository.loadDeferredContext(request).get();
                if(context != null && !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)){
                    var refreshToken = refreshTokenFactory.apply(context.getAuthentication());
                    var accessToken = accessTokenFactory.apply(refreshToken);

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                    Tokens tokens = new Tokens(accessTokenStringSerializer.apply(accessToken), accessToken.expiresAt().toString(),
                            refreshTokenStringSerializer.apply(refreshToken), refreshToken.expiresAt().toString());

                    objectMapper.writeValue(response.getWriter(), tokens);

                    return;
                }
            }

            throw new AccessDeniedException("Customer must be authenticated");
        }

        filterChain.doFilter(request, response);
    }
}
