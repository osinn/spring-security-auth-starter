package com.gitee.osinn.boot.securityjwt.service;

import com.gitee.osinn.boot.securityjwt.annotation.API;
import com.gitee.osinn.boot.securityjwt.annotation.APIMethodPermission;
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

    APIMethodPermission getServiceApiMethodPermissionAnnotation(HttpServletRequest request);

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
     * 从全部权限中查询是否存在该权限
     *
     * @param requestURI
     * @param request
     * @return 权限
     */
    @Deprecated
    List<ConfigAttribute> getConfigAttribute(String requestURI, HttpServletRequest request);


    boolean getIsApiService();
}
