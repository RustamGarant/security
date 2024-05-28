package com.app.security.service;

import com.app.security.dto.*;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import java.util.*;
import java.util.function.*;
import lombok.*;
import lombok.extern.slf4j.*;

@Slf4j
@AllArgsConstructor
public class TokenCookieJweStringSerializer implements Function<Token, String> {

    private final JWEEncrypter jweEncrypter;

    @Setter
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

    @Setter
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    public TokenCookieJweStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    @Override
    public String apply(Token token) {
        var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod)
            .keyID(token.getId().toString())
            .build();
        var claimsSet = new JWTClaimsSet.Builder()
            .jwtID(token.getId().toString())
            .subject(token.getSubject())
            .issueTime(Date.from(token.getCreatedAt()))
            .expirationTime(Date.from(token.getExpiresAt()))
            .claim("authorities", token.getAuthorities())
            .build();
        var encryptedJWT = new EncryptedJWT(jwsHeader, claimsSet);
        try {
            encryptedJWT.encrypt(this.jweEncrypter);

            return encryptedJWT.serialize();
        } catch (JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null;
    }
}
