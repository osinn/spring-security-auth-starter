package io.github.osinn.securitytoken.annotation;


import java.lang.annotation.*;

/**
 * 服务API注解，在方法上添加此注解校验方法权限
 *
 * @author wency_cai
 **/
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface APIMethodPermission {

    /**
     * 是否需要认证登录
     *
     * @return true 需要认证登录，false 不需要认证登录
     */
    boolean needLogin() default false;

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
    boolean needPermission() default false;
}
