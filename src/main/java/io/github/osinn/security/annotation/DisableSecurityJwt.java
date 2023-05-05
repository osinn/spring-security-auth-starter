package io.github.osinn.security.annotation;

import io.github.osinn.security.config.DisableSecurityAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * 禁用security jwt，如果引入此依赖包暂时不用 spring Security 功能，
 * 必须在启动类是使用 @DisableSecurityJwt注解禁用自动配置
 *
 * @author wency_cai
 **/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import(DisableSecurityAutoConfiguration.class)
public @interface DisableSecurityJwt {
}
