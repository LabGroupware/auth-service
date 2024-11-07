package org.cresplanex.account.oauth.config;

import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;

public class FlywayConfiguration {

    @Bean
    public FlywayMigrationStrategy flywayMigrationStrategy() {
        return flyway -> {
            // DDLマイグレーションを先に実行
            Flyway ddlFlyway = Flyway.configure()
                    .locations("classpath:db/migration/ddl")
                    .dataSource(flyway.getConfiguration().getDataSource())
                    .load();
            ddlFlyway.migrate();

            // データマイグレーションを実行
            Flyway dataFlyway = Flyway.configure()
                    .locations("classpath:db/migration/data/common")
                    .dataSource(flyway.getConfiguration().getDataSource())
                    .load();
            dataFlyway.migrate();

            // ダミーデータマイグレーションを実行
            Flyway dummyDataFlyway = Flyway.configure()
                    .locations("classpath:db/migration/data/dummy")
                    .dataSource(flyway.getConfiguration().getDataSource())
                    .load();
            dummyDataFlyway.migrate();
        };
    }
}

