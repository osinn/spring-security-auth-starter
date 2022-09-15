package io.github.osinn.securitytoken.service;

import io.github.osinn.securitytoken.annotation.API;
import io.github.osinn.securitytoken.annotation.APIMethodPermission;
import io.github.osinn.securitytoken.security.dto.ResourcePermission;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;

public interface IApiAuthService {

    /**
     * 获取服务API注解
     *
     * @param request
     * @return 返回@APIHandlerMethod 或 @API
     */
    API getServiceApiAnnotation(HttpServletRequest request);

    /**
     * 获取服务API注解方法上的权限注解
     *
     * @param serviceName 服务名称
     * @return 返回@APIHandlerMethod 或 @API
     */
    APIMethodPermission getServiceApiMethodPermissionAnnotation(String serviceName);

    /**
     * @param request
     * @return true-不需要登录认证，false-登录认证
     */
    boolean checkAnonymousService(HttpServletRequest request);


    /**
     * 从全部权限中查询是否存在该权限
     *
     * @param api
     * @param request
     * @param authorities
     * @return 权限
     */
    void checkAttribute(API api, HttpServletRequest request, Collection<? extends GrantedAuthority> authorities);

    /**
     * 根据url认证访问权限
     *
     * @param requestURI          当前访问的路径
     * @param resourcePermissions 拥有的资源权限
     * @return 权限
     */
    void checkResourcePermissionUriPath(String requestURI, Collection<ResourcePermission> resourcePermissions, HttpServletRequest request);


    boolean getIsApiService();
}
