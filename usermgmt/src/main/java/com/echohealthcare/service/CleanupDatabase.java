package com.echohealthcare.service;

import java.time.LocalDateTime;
import java.sql.Timestamp;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class CleanupDatabase {

    @Value("${clean.database.days}")
    Integer days;

        private static final String SQL_DELETE_OAUTH2_AUTHORIZATION = """
            DELETE FROM oauth2_authorization WHERE (authorization_code_expires_at < :threshold OR authorization_code_expires_at IS NULL)
            AND (access_token_expires_at < :threshold OR access_token_expires_at IS NULL)
            AND (oidc_id_token_expires_at < :threshold OR oidc_id_token_expires_at IS NULL)
            AND (refresh_token_expires_at < :threshold OR refresh_token_expires_at IS NULL)
            AND (device_code_expires_at < :threshold OR device_code_expires_at IS NULL)
            AND (user_code_expires_at < :threshold OR user_code_expires_at IS NULL);
            """;
    private static final String SQL_COUNT_OAUTH2_AUTHORIZATION = """
			SELECT COUNT(*) FROM oauth2_authorization;
			""";
    private final JdbcClient jdbcClient;

    public CleanupDatabase(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Scheduled(cron="${clean.database.cron.expression}")
    public void cleanupExpiredTokens() {
        System.err.println("CleanUp: " + LocalDateTime.now());
        LocalDateTime cutoff = LocalDateTime.now().minusDays(days == null ? 0 : days);
        Timestamp threshold = Timestamp.valueOf(cutoff);
        jdbcClient.sql(SQL_DELETE_OAUTH2_AUTHORIZATION)
            .param("threshold", threshold)
            .update();
        System.err.println(jdbcClient.sql(SQL_COUNT_OAUTH2_AUTHORIZATION).query(Integer.class).single());
    }
}
