package io.github.osinn.security.security;

import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.ResourcePermission;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.service.ISecurityService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;

/**
 * 自定安全元数据源
 *
 * @author wency_cai
 */
public class CustomSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {


    private ISecurityService securityService;

    private AuthType authType;

    /**
     * 白名单
     */
    private SecurityStorage securityStorage;

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    public CustomSecurityMetadataSource(ISecurityService securityService,
                                        SecurityStorage securityStorage,
                                        AuthType authType) {
        this.securityService = securityService;
        this.securityStorage = securityStorage;
        this.authType = authType;
    }

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        HttpServletRequest request = (HttpServletRequest)object;

        if (securityStorage.isAnonymousUri(request)) {
            // 放行白名单
            return SecurityConfig.createList();
        }

        //从数据库加载全部权限配置
        List<ResourcePermission> resourcePermissionList = securityService.getSysResourcePermissionAll();
        if (resourcePermissionList != null && !resourcePermissionList.isEmpty()) {
            if (AuthType.OFF.equals(authType)) {
                return SecurityConfig.createList();
            } else if (AuthType.CODE.equals(authType)) {
                String url = request.getRequestURI();
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    // 对比系统权限资源
                    if (antPathMatcher.match(resourcePermission.getUriPath(), url)) {
                        return SecurityConfig.createList(resourcePermission.getPermissionCode().trim());
                    }
                }
            } else {
                String url = request.getRequestURI();
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    // 对比系统权限资源
                    if (antPathMatcher.match(resourcePermission.getUriPath(), url)) {
                        return SecurityConfig.createList(resourcePermission.getUriPath().trim());
                    }
                }
            }
        }

        //  返回代码定义的默认配置
        return SecurityConfig.createList();
    }


    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

}