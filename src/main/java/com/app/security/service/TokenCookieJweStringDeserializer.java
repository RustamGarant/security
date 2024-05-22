package com.app.security.service;

import com.app.security.dto.*;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import java.text.*;
import java.util.*;
import java.util.function.*;
import lombok.extern.slf4j.*;

@Slf4j
public class TokenCookieJweStringDeserializer implements Function<String, Token> {

    private final JWEDecrypter jweDecrypter;

    public TokenCookieJweStringDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    @Override
    public Token apply(String string) {
        try {
            var encryptedJWT = EncryptedJWT.parse(string);
            encryptedJWT.decrypt(this.jweDecrypter);
            var claimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                claimsSet.getStringListClaim("authorities"),
                claimsSet.getIssueTime().toInstant(),
                claimsSet.getExpirationTime().toInstant());
        } catch (ParseException | JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null;
    }
}