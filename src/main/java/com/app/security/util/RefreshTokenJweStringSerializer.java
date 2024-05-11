package com.app.security.util;

import com.app.security.dto.RefreshToken;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.Date;
import java.util.function.Function;

@Slf4j
@RequiredArgsConstructor
public class RefreshTokenJweStringSerializer implements Function<RefreshToken, String> {

    private final JWEEncrypter jweEncrypter;
    private final JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;
    private final EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    @Override
    public String apply(RefreshToken refreshToken) {
        JWEHeader jwsHeader = new JWEHeader.Builder(jweAlgorithm, encryptionMethod)
                .keyID(refreshToken.id().toString())
                .build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(refreshToken.id().toString())
                .subject(refreshToken.subject())
                .issueTime(Date.from(refreshToken.createdAt()))
                .expirationTime(Date.from(refreshToken.expiresAt()))
                .claim("authorities", refreshToken.authorities())
                .build();
        var encryptedJWT = new EncryptedJWT(jwsHeader, jwtClaimsSet);

        try {
            encryptedJWT.encrypt(jweEncrypter);
        } catch (JOSEException e){
            log.error(e.getMessage(), e);
        }
        return encryptedJWT.serialize();
    }
}
