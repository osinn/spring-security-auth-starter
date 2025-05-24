package io.github.osinn.security.annotation;

import io.github.osinn.security.config.DisableSecurityAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * 禁用security auth，如果引入此依赖包暂时不用 spring Security 功能，
 * 必须在启动类是使用 @DisableSecurityAuth注解禁用自动配置
 * 作用不是很大，当存在注入 IOnlineUserService 这些内置当对象时，启动会因为无法注入而报错
 *
 * @author wency_cai
 **/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@Import(DisableSecurityAutoConfiguration.class)
public @interface DisableSecurityAuth {
}
