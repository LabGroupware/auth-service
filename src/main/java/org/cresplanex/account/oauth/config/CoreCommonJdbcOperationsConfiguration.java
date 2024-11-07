package org.cresplanex.account.oauth.config;

import org.cresplanex.core.common.jdbc.*;
import org.cresplanex.core.common.jdbc.sqldialect.CoreSqlDialect;
import org.cresplanex.core.common.jdbc.sqldialect.SqlDialectConfiguration;
import org.cresplanex.core.common.jdbc.sqldialect.SqlDialectSelector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Collection;

@Configuration
@Import({CoreSchemaConfiguration.class,
    SqlDialectConfiguration.class,
    OutboxPartitioningSpecConfiguration.class})
public class CoreCommonJdbcOperationsConfiguration {

    @Bean
    public SqlDialectSelector sqlDialectSelector(Collection<CoreSqlDialect> dialects) {
        return new SqlDialectSelector(dialects);
    }

    /**
     * Spring JDBCのSQL生成テンプレートを利用.
     */
    @Bean
    public CoreTransactionTemplate coreTransactionTemplate(TransactionTemplate transactionTemplate) {
        return new CoreSpringTransactionTemplate(transactionTemplate);
    }

    /**
     * Spring JDBCをExecutorに使用.
     */
    @Bean
    public CoreJdbcStatementExecutor coreJdbcStatementExecutor(JdbcTemplate jdbcTemplate) {
        return new CoreSpringJdbcStatementExecutor(jdbcTemplate);
    }

    @Bean
    public CoreCommonJdbcOperations coreCommonJdbcOperations(CoreJdbcStatementExecutor coreJdbcStatementExecutor,
            SqlDialectSelector sqlDialectSelector,
            @Value("${spring.datasource.driver-class-name}") String driver,
            OutboxPartitioningSpec outboxPartitioningSpec) {
        CoreSqlDialect coreSqlDialect = sqlDialectSelector.getDialect(driver);
        return new CoreCommonJdbcOperations(new CoreJdbcOperationsUtils(coreSqlDialect),
                coreJdbcStatementExecutor, coreSqlDialect, outboxPartitioningSpec);
    }
}
