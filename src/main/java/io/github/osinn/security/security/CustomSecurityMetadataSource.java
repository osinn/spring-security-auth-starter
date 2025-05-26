package io.github.osinn.security.security;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.ResourcePermission;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.RedisUtils;
import io.github.osinn.security.utils.StrUtils;
import io.github.osinn.security.utils.TokenUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 自定安全元数据源
 *
 * @author wency_cai
 */
public class CustomSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {


    private final ISecurityService securityService;

    private final AuthType authType;

    /**
     * 白名单
     */
    private final SecurityStorage securityStorage;

    private final SecurityProperties securityProperties;

    private final RedisUtils redisUtils;

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    public CustomSecurityMetadataSource(ISecurityService securityService,
                                        SecurityStorage securityStorage,
                                        SecurityProperties securityProperties,
                                        RedisUtils redisUtils,
                                        AuthType authType) {
        this.securityService = securityService;
        this.securityStorage = securityStorage;
        this.securityProperties = securityProperties;
        this.redisUtils = redisUtils;
        this.authType = authType;
    }

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        HttpServletRequest request = (HttpServletRequest) object;

        if (securityStorage.isAnonymousUri(request)) {
            // 放行白名单
            return SecurityConfig.createList();
        }

        String token = TokenUtils.getToken();
        if (token != null && securityProperties.getIgnoringToken().contains(securityProperties.getTokenStartWith() + token)) {
            // 白名单token放行
            return SecurityConfig.createList();
        }

        //从数据库加载全部权限配置
        List<ResourcePermission> resourcePermissionList = this.getSysResourcePermissionAll();

        if (resourcePermissionList != null && !resourcePermissionList.isEmpty()) {
            if (AuthType.OFF.equals(authType)) {
                return SecurityConfig.createList();
            } else if (AuthType.CODE.equals(authType)) {
                List<String> permissionCodes = new ArrayList<>();
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    // 对比系统权限资源
                    if (!StrUtils.isEmpty(resourcePermission.getPermissionCode())) {
                        permissionCodes.add(resourcePermission.getPermissionCode());
                    }
                }
                return SecurityConfig.createList(permissionCodes.toArray(new String[0]));
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

    private List<ResourcePermission> getSysResourcePermissionAll() {
        List<ResourcePermission> resourcePermissionList;
        if (securityProperties.isEnableSysResourcePermissionAll()) {
            resourcePermissionList = redisUtils.getList(AuthConstant.SYS_RESOURCE_PERMISSION_ALL_CACHE_KEY);
            if (CollectionUtils.isEmpty(resourcePermissionList)) {
                resourcePermissionList = securityService.getSysResourcePermissionAll();
                redisUtils.set(AuthConstant.SYS_RESOURCE_PERMISSION_ALL_CACHE_KEY, resourcePermissionList);
            }
        } else {
            resourcePermissionList = securityService.getSysResourcePermissionAll();
        }

        return resourcePermissionList;
    }
}
