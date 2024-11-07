package io.github.osinn.securitytoken.security;

import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.security.dto.ResourcePermission;
import io.github.osinn.securitytoken.security.dto.SecurityStorage;
import io.github.osinn.securitytoken.service.ISecurityService;
import io.github.osinn.securitytoken.starter.SecurityJwtProperties;
import io.github.osinn.securitytoken.utils.StrUtils;
import io.github.osinn.securitytoken.utils.TokenUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
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

    private SecurityJwtProperties securityJwtProperties;

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    public CustomSecurityMetadataSource(ISecurityService securityService,
                                        SecurityStorage securityStorage,
                                        SecurityJwtProperties securityJwtProperties) {
        this.securityService = securityService;
        this.securityStorage = securityStorage;
        this.securityJwtProperties = securityJwtProperties;
        this.authType = securityJwtProperties.getAuthType();
    }

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        FilterInvocation fi = (FilterInvocation) object;
        HttpServletRequest request = fi.getHttpRequest();

        if (securityStorage.isAnonymousUri(request)) {
            // 放行白名单
            return SecurityConfig.createList();
        }

        String token = TokenUtils.getToken();
        if (token != null && securityJwtProperties.getIgnoringToken().contains(securityJwtProperties.getTokenStartWith() + token)) {
            // 白名单token放行
            return SecurityConfig.createList();
        }

        //从数据库加载全部权限配置
        List<ResourcePermission> resourcePermissionList = securityService.getSysResourcePermissionAll();
        if (resourcePermissionList != null && !resourcePermissionList.isEmpty()) {
            if (AuthType.OFF.equals(authType)) {
                return SecurityConfig.createList();
            } else if (AuthType.CODE.equals(authType)) {
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    // 对比系统权限资源
                    if (StrUtils.isEmpty(resourcePermission.getPermissionCode())) {
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
