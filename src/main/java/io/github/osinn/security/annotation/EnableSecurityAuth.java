package io.github.osinn.security.annotation;

import io.github.osinn.security.config.AuthAppRun;
import io.github.osinn.security.config.SecurityConfig;
import io.github.osinn.security.starter.SecurityAutoConfigure;
import io.github.osinn.security.utils.SpringContextHolder;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 启用security auth
 *
 * @author wency_cai
 **/
@Import({SecurityAutoConfigure.class, SecurityConfig.class, SpringContextHolder.class, AuthAppRun.class})
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface EnableSecurityAuth {
}
