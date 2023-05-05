package io.github.osinn.security.service.impl;

import io.github.osinn.security.annotation.API;
import io.github.osinn.security.annotation.APIMethodPermission;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.enums.JwtHttpStatus;
import io.github.osinn.security.exception.SecurityJwtException;
import io.github.osinn.security.security.dto.ResourcePermission;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.service.IApiAuthService;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.utils.StrUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ApiAuthServiceImpl implements IApiAuthService {

    @Autowired
    private ISecurityService securityService;

    /**
     * 白名单
     */
    @Autowired
    private SecurityStorage securityStorage;

    private AuthType authType;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 可选- 如果是api服务层,前端需要传参数：接口方法名称
     * 如果设置为true，需要serviceHandlerMethod 指定前端要调用的方法的参数名称
     * 这时前端不只是传serviceName 需要调用的服务，还要传 serviceHandlerMethod具体要调用服务下的哪个接口方法
     */
    private final boolean apiService;


    public ApiAuthServiceImpl(AuthType authType, boolean apiService) {
        this.authType = authType;
        this.apiService = apiService;
    }

    @Override
    public API getServiceApiAnnotation(HttpServletRequest request) {
        Map<String, API> apiMap = securityStorage.getApiMap();
        String serviceName = securityService.getServiceName(request);
        API api = apiMap.get(serviceName);
        if (api != null) {
            return api;
        } else {
            throw new SecurityJwtException(JwtHttpStatus.NOT_FOUND.getCode(), "服务不存在");
        }
    }

    @Override
    public APIMethodPermission getServiceApiMethodPermissionAnnotation(String serviceName) {
        if (StrUtils.isEmpty(serviceName)) {
            return null;
        }
        Map<String, APIMethodPermission> apiMethodPermissions = securityStorage.getApiMethodPermissions();
        return apiMethodPermissions == null ? null : apiMethodPermissions.get(serviceName);
    }

    @Override
    public boolean checkAnonymousService(HttpServletRequest request) {
        // 判断基于API服务名称请求是否白名单
        API serviceApiAnnotation = getServiceApiAnnotation(request);
        if (serviceApiAnnotation == null) {
            throw new SecurityJwtException(JwtHttpStatus.NOT_FOUND.getCode(), "服务不存在");
        }
        APIMethodPermission serviceApiMethodPermissionAnnotation = getServiceApiMethodPermissionAnnotation(serviceApiAnnotation.service());
        if (serviceApiMethodPermissionAnnotation != null) {
            return !serviceApiMethodPermissionAnnotation.needLogin();
        }
        return !serviceApiAnnotation.needLogin();
    }

    @Override
    public boolean checkAttribute(API api, HttpServletRequest request, Collection<? extends GrantedAuthority> authorities) {
        if (api != null) {
            APIMethodPermission serviceApiMethodPermissionAnnotation = this.getServiceApiMethodPermissionAnnotation(api.service());
            if (serviceApiMethodPermissionAnnotation != null && serviceApiMethodPermissionAnnotation.needPermission()) {
                // 方法级别权限认证
                return this.checkAuthCode(serviceApiMethodPermissionAnnotation.permission(), request, authorities);
            } else if (api.needPermission()) {
                // 服务级别权限认证
                return this.checkAuthCode(api.permission(), request, authorities);
            } else {
                return true;
            }
        } else {
            request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "当前访问没有权限");
            return false;
        }
    }

    @Override
    public void checkResourcePermissionUriPath(String requestURI, Collection<ResourcePermission> resourcePermissions, HttpServletRequest request) {
        if (AuthType.URL.equals(authType)) {
            for (ResourcePermission resourcePermission : resourcePermissions) {
                if (!StrUtils.isEmpty(resourcePermission.getUriPath()) && antPathMatcher.match(resourcePermission.getUriPath(), requestURI)) {
                    return;
                }
            }
        }
        request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "当前访问没有权限");
        throw new AccessDeniedException("当前访问没有权限");
    }

    @Override
    public boolean getIsApiService() {
        return apiService;
    }

    private boolean checkAuthCode(String needCode, HttpServletRequest request, Collection<? extends GrantedAuthority> authorities) {
        if (StrUtils.isEmpty(needCode)) {
            return true;
        }
        for (GrantedAuthority authority : authorities) {
            if (Objects.equals(needCode, authority.getAuthority())) {
                return true;
            }
        }
        request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "当前访问没有权限");
        return false;
    }

    public static void main(String[] args) {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        System.out.println(antPathMatcher.match("/auth", "/auth"));
    }
}
