package io.github.osinn.security.config;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

/**
 * 禁用自动配置
 *
 * @author wency_cai
 **/
@EnableAutoConfiguration(exclude = {
        SecurityAutoConfiguration.class
})
public class DisableSecurityAutoConfiguration {
}
