package com.app.security.util;

import com.app.security.dto.AccessToken;
import com.app.security.dto.RefreshToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@RequiredArgsConstructor
@Setter
@Slf4j
public class RefreshTokenJweStringDeserializer implements Function<String, RefreshToken> {

    private final JWEDecrypter decrypter;

    @Override
    public RefreshToken apply(String s) {
        try {
            var encryptedJwt = EncryptedJWT.parse(s);
            encryptedJwt.decrypt(decrypter);
            var claimSet = encryptedJwt.getJWTClaimsSet();
            return new RefreshToken(UUID.fromString(claimSet.getJWTID()), claimSet.getSubject(),
                    claimSet.getStringListClaim("Authorities"),
                    claimSet.getIssueTime().toInstant(),
                    claimSet.getExpirationTime().toInstant());

        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
