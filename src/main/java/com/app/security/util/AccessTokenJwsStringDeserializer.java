package com.app.security.util;

import com.app.security.dto.AccessToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@RequiredArgsConstructor
@AllArgsConstructor
@Setter
@Slf4j
public class AccessTokenJwsStringDeserializer implements Function<String, AccessToken> {

    private final JWSVerifier verifier;

    @Override
    public AccessToken apply(String s) {
        try{
            var signedJWT = SignedJWT.parse(s);
            if (signedJWT.verify(verifier)){
                var claimSet = signedJWT.getJWTClaimsSet();
                return new AccessToken(UUID.fromString(claimSet.getJWTID()), claimSet.getSubject(),
                        claimSet.getStringListClaim("Authorities"),
                        claimSet.getIssueTime().toInstant(),
                        claimSet.getExpirationTime().toInstant());
            }
        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
