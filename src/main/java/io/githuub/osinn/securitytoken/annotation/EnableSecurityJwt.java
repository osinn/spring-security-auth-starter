package io.githuub.osinn.securitytoken.annotation;

import io.githuub.osinn.securitytoken.config.JwtAppRun;
import io.githuub.osinn.securitytoken.config.SecurityConfig;
import io.githuub.osinn.securitytoken.starter.SecurityAutoConfigure;
import io.githuub.osinn.securitytoken.utils.SpringContextHolder;
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
