package io.github.osinn.security.security;

import cn.hutool.core.collection.CollUtil;
import io.github.osinn.security.annotation.API;
import io.github.osinn.security.annotation.APIMethodPermission;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.service.IApiAuthService;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Collection;
import java.util.List;
import java.util.Objects;


/**
 * 自定义访问决策(code认证不会进来，使用默认的认证)
 *
 * @author wency_cai
 */
@Slf4j
public class CustomAccessDecisionManager {


    /**
     * 白名单
     */
    private SecurityStorage securityStorage;


    private IApiAuthService apiAuthService;

    private AuthType authType;

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(SecurityStorage securityStorage,
                                       IApiAuthService apiAuthService,
                                       AuthType authType) {
        this.securityStorage = securityStorage;
        this.apiAuthService = apiAuthService;
        this.authType = authType;
    }

    public boolean decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {

        if (AuthType.OFF.equals(authType)) {
            // 权限认证关闭状态¸不需要认证权限，放行
            return true;
        }

        // 当系统没有配置权限资源时直接放行
        if (CollUtil.isEmpty(configAttributes)) {
            return true;
        }

        HttpServletRequest request = (HttpServletRequest) object;

        if (securityStorage.isAnonymousUri(request)) {
            // 放行白名单
            return true;
        }

        if (authentication == null) {
            throw new AccessDeniedException("当前访问没有权限");
        }

        OnlineUser onlineUser = (OnlineUser) authentication.getPrincipal();

        Boolean hasRoleAdmin = TokenUtils.hasRoleAdmin(onlineUser.getRoles());
        if (Boolean.TRUE.equals(hasRoleAdmin)) {
            return true;
        }

        if (AuthType.SERVICE.equals(authType)) {
            API api = apiAuthService.getServiceApiAnnotation(request);
//            APIMethodPermission serviceApiMethodPermissionAnnotation = apiAuthService.getServiceApiMethodPermissionAnnotation(api.service());
//            if (serviceApiMethodPermissionAnnotation != null) {
//                if (!serviceApiMethodPermissionAnnotation.needPermission()) {
//                    return true;
//                }
//            } else if (!api.needPermission()) {
//                return true;
//            }

            // 检查是否有权限访问
            return apiAuthService.checkAttribute(api, request, authentication.getAuthorities());
        } else if (AuthType.URL.equals(authType)) {
            boolean authority = false;
            for (ConfigAttribute configAttribute : configAttributes) {
                //资源比对系统权限
                String needAuthority = configAttribute.getAttribute();
                if (Objects.equals(needAuthority, request.getRequestURI())) {
                    authority = true;
                    break;
                }
            }

            // 请求路径在权限表中，需要认证权限，否则放行
            if (!authority) {
                return true;
            }
            /**
             * 后面将删除此方法，直接调用 authentication.getAuthorities()
             */
            apiAuthService.checkResourcePermissionUriPath(request.getRequestURI(), onlineUser.getResourcePermissions(), request);

            return true;

        } else if (AuthType.CODE.equals(authType)) {
            for (ConfigAttribute configAttribute : configAttributes) {
                //将系统访问所需资源与用户拥有资源进行比对
                String needAuthority = configAttribute.getAttribute();
                for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
                    if (needAuthority.trim().equals(grantedAuthority.getAuthority())) {
                        return true;
                    }
                }
            }
        }
        return true;

    }


}