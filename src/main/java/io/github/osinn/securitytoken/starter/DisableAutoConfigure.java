package io.github.osinn.securitytoken.starter;

import io.github.osinn.securitytoken.annotation.DisableSecurityJwt;
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
