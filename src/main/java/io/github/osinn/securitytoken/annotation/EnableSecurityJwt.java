package io.github.osinn.securitytoken.annotation;

import io.github.osinn.securitytoken.config.JwtAppRun;
import io.github.osinn.securitytoken.config.SecurityConfig;
import io.github.osinn.securitytoken.starter.SecurityAutoConfigure;
import io.github.osinn.securitytoken.utils.SpringContextHolder;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author wency
 * @description: 启用security jwt
 **/
@Import({SecurityAutoConfigure.class, SecurityConfig.class, SpringContextHolder.class, JwtAppRun.class})
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface EnableSecurityJwt {
}
