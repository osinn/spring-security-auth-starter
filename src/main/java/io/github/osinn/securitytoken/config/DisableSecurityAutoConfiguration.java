package io.github.osinn.securitytoken.config;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * 禁用自动配置
 *
 * @author wency_cai
 **/
@EnableAutoConfiguration(exclude = {
        org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
        org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration.class
})
public class DisableSecurityAutoConfiguration {
}
