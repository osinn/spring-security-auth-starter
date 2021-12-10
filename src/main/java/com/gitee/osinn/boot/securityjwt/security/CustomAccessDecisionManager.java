package com.gitee.osinn.boot.securityjwt.security;

import com.gitee.osinn.boot.securityjwt.security.dto.PermissionAnonymousUri;
import com.gitee.osinn.boot.securityjwt.security.dto.ResourcePermission;
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
import com.gitee.osinn.boot.securityjwt.enums.AuthType;
import com.gitee.osinn.boot.securityjwt.service.ISecurityService;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;


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
    private PermissionAnonymousUri permissionAnonymousUri;

    private ISecurityService securityService;

    private AuthType authType;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(PermissionAnonymousUri permissionAnonymousUri,
                                       ISecurityService securityService,
                                       AuthType authType) {
        this.permissionAnonymousUri = permissionAnonymousUri;
        this.securityService = securityService;
        this.authType = authType;
    }

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {

        FilterInvocation filterInvocation = (FilterInvocation) object;
        HttpServletRequest request = filterInvocation.getRequest();

        if (permissionAnonymousUri.isAnonymousUri(request)) {
            // 放行白名单
            return;
        }
//
//        String tokenError = (String) request.getAttribute(JwtHttpStatus.TOKEN_EXPIRE.name());
//        if (tokenError != null) {
//            throw new AccessDeniedException(tokenError);
//        }

        String requestURI = request.getRequestURI();

        List<ConfigAttribute> configAttributeList = getConfigAttribute(requestURI, request);

        /**
         * 判断是否有权限访问
         */
        Iterator<ConfigAttribute> iterator = configAttributeList.iterator();
        while (iterator.hasNext()) {

            if (authentication == null) {
                throw new AccessDeniedException("当前访问没有权限");
            }

            ConfigAttribute configAttribute = iterator.next();
            String needCode = configAttribute.getAttribute();
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
                    if (!StringUtils.isEmpty(resourcePermission.getUriPath())
                            && antPathMatcher.match(resourcePermission.getUriPath(), requestURI)) {
                        request.setAttribute("accessDecisionMenuName", resourcePermission.getMenuName());
                        return SecurityConfig.createList(resourcePermission.getPermissionCode());
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