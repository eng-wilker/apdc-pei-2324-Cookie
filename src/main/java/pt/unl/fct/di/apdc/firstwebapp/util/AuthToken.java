package pt.unl.fct.di.apdc.firstwebapp.util;

import java.time.Instant;
import java.util.UUID;

public class AuthToken {
    public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 2;  // 2 hours
    public String username;
    public String tokenID;
    public long creationData;
    public long expirationData;
    public String role;

    public AuthToken() {

    }

    public AuthToken(String username, String role) {
        this.role = role;
        this.username = username;
        this.tokenID = UUID.randomUUID().toString();
        this.creationData = System.currentTimeMillis();
        this.expirationData = this.creationData + AuthToken.EXPIRATION_TIME;
    }

    public String getUsername() {
        return username;
    }
    public String getFields() {
        return username + "." + tokenID + "." + role + "." + creationData + "." + expirationData;
    }

    public static boolean isTokenExpired( Long expirationData2) {
        long currentTime = Instant.now().toEpochMilli();
        return currentTime >= expirationData2;
    }
    public String getRole() {
        return role;
    }
}