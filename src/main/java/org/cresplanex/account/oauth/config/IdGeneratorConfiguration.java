package org.cresplanex.account.oauth.config;

import org.cresplanex.core.common.id.CoreIdGeneratorConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import(CoreIdGeneratorConfiguration.class)
public class IdGeneratorConfiguration {
}