package com.gitee.osinn.boot.securityjwt.security;

import com.gitee.osinn.boot.securityjwt.annotation.API;
import com.gitee.osinn.boot.securityjwt.enums.AuthType;
import com.gitee.osinn.boot.securityjwt.enums.JwtHttpStatus;
import com.gitee.osinn.boot.securityjwt.exception.SecurityJwtException;
import com.gitee.osinn.boot.securityjwt.security.dto.ResourcePermission;
import com.gitee.osinn.boot.securityjwt.security.dto.SecurityStorage;
import com.gitee.osinn.boot.securityjwt.service.ISecurityService;
import com.gitee.osinn.boot.securityjwt.utils.StrUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;
import java.util.Map;


/**
 * 自定义访问决策
 *
 * @author wency_cai
 */
@Slf4j
public class CustomAccessDecisionManager implements AccessDecisionManager {


    /**
     * 白名单
     */
    private SecurityStorage securityStorage;

    private ISecurityService securityService;

    private AuthType authType;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(SecurityStorage securityStorage,
                                       ISecurityService securityService,
                                       AuthType authType) {
        this.securityStorage = securityStorage;
        this.securityService = securityService;
        this.authType = authType;
    }

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {

        if (AuthType.OFF.equals(authType)) {
            // 权限认证关闭状态¸不需要认证权限，放行
            return;
        }

        FilterInvocation filterInvocation = (FilterInvocation) object;
        HttpServletRequest request = filterInvocation.getRequest();
        List<ConfigAttribute> configAttributeList;

        if (AuthType.SERVICE.equals(authType)) {

            Map<String, API> apiServiceMap = securityStorage.getApiServiceMap();
            String serviceName = securityService.getServiceName(request);
            API api = apiServiceMap.get(serviceName);
            if (api != null) {
                if (!api.needPermission()) {
                    // 不需要权限认证-放行
                    return;
                }
            } else {
                throw new SecurityJwtException(JwtHttpStatus.NOT_FOUND.getCode(), "服务不存在");
            }

            configAttributeList = this.getApiConfigAttribute(api, request);

        } else {
            if (securityStorage.isAnonymousUri(request)) {
                // 放行白名单
                return;
            }

            configAttributeList = getConfigAttribute(request.getRequestURI(), request);

        }

        /**
         * 判断是否有权限访问
         */
        for (ConfigAttribute attribute : configAttributeList) {

            if (authentication == null) {
                throw new AccessDeniedException("当前访问没有权限");
            }

            String needCode = attribute.getAttribute();
            if (needCode != null) {
                Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
                for (GrantedAuthority authority : authorities) {
                    if (authority.getAuthority().equals(needCode)) {
                        return;
                    }
                }
            }

        }

        throw new AccessDeniedException("当前访问没有权限");
    }

    private List<ConfigAttribute> getConfigAttribute(String requestURI, HttpServletRequest request) {

        if (AuthType.URL.equals(authType)) {
            //从数据库加载全部权限配置
            List<ResourcePermission> resourcePermissionList = securityService.fetchResourcePermissionAll();
            if (resourcePermissionList != null) {
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    if (!StrUtils.isEmpty(resourcePermission.getUriPath())
                            && antPathMatcher.match(resourcePermission.getUriPath(), requestURI)) {
                        request.setAttribute("accessDecisionMenuName", resourcePermission.getMenuName());
                        return SecurityConfig.createList(resourcePermission.getPermissionCode());
                    }
                }
            }
        }
        throw new AccessDeniedException("当前访问没有权限");
    }

    private List<ConfigAttribute> getApiConfigAttribute(API api, HttpServletRequest request) {

        if (AuthType.SERVICE.equals(authType)) {
            //从数据库加载全部权限配置
            List<ResourcePermission> resourcePermissionList = securityService.fetchResourcePermissionAll();
            if (resourcePermissionList != null) {
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    if (api != null) {
                        if (api.permission().equals(resourcePermission.getPermissionCode())) {
                            request.setAttribute("accessDecisionMenuName", resourcePermission.getMenuName());
                            return SecurityConfig.createList(resourcePermission.getPermissionCode());
                        }
                    }
                }
            }
        }
        throw new AccessDeniedException("当前访问没有权限");
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

}