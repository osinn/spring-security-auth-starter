package io.github.osinn.securitytoken.annotation;


import org.springframework.stereotype.Component;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 服务API注解，在类上添加此注解
 * <p>
 * 有时候我们调用的接口是通过注解指定服务名称
 * 前端通过指定服务名称调用接口
 * </p>
 *
 * @author wency_cai
 **/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Component
public @interface API {

    /**
     * 服务名称-应用场景：用于通过服务名称调用接口指定的服务名称
     *
     * @return 服务名称
     */
    String service();

    /**
     * 是否需要认证登录
     *
     * @return true 需要认证登录，false 不需要认证登录
     */
    boolean needLogin() default true;

    /**
     * 接口拥有的权限
     *
     * @return 权限code
     */
    String permission() default "";

    /**
     * 是否需要权限认证
     *
     * @return true 需要认证权限，false 不需要认证权限
     */
    boolean needPermission() default true;
}
