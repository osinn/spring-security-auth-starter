package io.github.osinn.security.starter;

import io.github.osinn.security.annotation.DisableSecurityJwt;
import org.springframework.context.annotation.Configuration;

/**
 * 禁用自动配置
 *
 * @author wency_cai
 */
@Configuration
@DisableSecurityJwt
public class DisableAutoConfigure {

}
