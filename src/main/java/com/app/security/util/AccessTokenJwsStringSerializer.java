package com.app.security.util;

import com.app.security.dto.AccessToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.sql.Date;
import java.util.function.Function;

@Slf4j
public class AccessTokenJwsStringSerializer implements Function<AccessToken, String> {

    private JWSSigner jwsSigner;
    private final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    /**
     * Serializes access Token to String
     * Set Headers and Claims to token
     * @param accessToken the function argument
     * @return
     */
    @Override
    public String apply(AccessToken accessToken) {
        JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlgorithm)
                .keyID(accessToken.id.toString())
                .build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .jwtID(accessToken.id.toString())
                .subject(accessToken.subject)
                .issueTime(Date.from(accessToken.createdAt))
                .expirationTime(Date.from(accessToken.expiresAt))
                .claim("authorities", accessToken.authorities)
                .build();
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);

        try {
            signedJWT.sign(jwsSigner);
        } catch (JOSEException e){
            log.error(e.getMessage(), e);
        }
        return signedJWT.serialize();
    }
}
