package com.gitee.osinn.boot.securityjwt.annotation;

import com.gitee.osinn.boot.securityjwt.config.JwtAppRun;
import com.gitee.osinn.boot.securityjwt.config.SecurityConfig;
import com.gitee.osinn.boot.securityjwt.starter.SecurityAutoConfigure;
import com.gitee.osinn.boot.securityjwt.utils.SpringContextHolder;
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
