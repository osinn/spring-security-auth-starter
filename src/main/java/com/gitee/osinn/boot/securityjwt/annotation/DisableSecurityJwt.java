package com.gitee.osinn.boot.securityjwt.annotation;

import com.gitee.osinn.boot.securityjwt.config.DisableSecurityAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * @author wency
 * @description: 禁用security jwt，如果引入此依赖包暂时不用 spring Security 功能，
 * 必须在启动类是使用 @DisableSecurityJwt注解禁用自动配置
 **/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import(DisableSecurityAutoConfiguration.class)
public @interface DisableSecurityJwt {
}
