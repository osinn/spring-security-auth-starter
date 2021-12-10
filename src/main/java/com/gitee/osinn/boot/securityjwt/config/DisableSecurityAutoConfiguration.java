package com.gitee.osinn.boot.securityjwt.config;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

@EnableAutoConfiguration(exclude = {
        org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
        org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration.class
})
public class DisableSecurityAutoConfiguration {
}
