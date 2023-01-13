package io.github.osinn.securitytoken.security;

import cn.hutool.core.collection.CollUtil;
import io.github.osinn.securitytoken.annotation.API;
import io.github.osinn.securitytoken.annotation.APIMethodPermission;
import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.security.dto.OnlineUser;
import io.github.osinn.securitytoken.security.dto.SecurityStorage;
import io.github.osinn.securitytoken.service.IApiAuthService;
import io.github.osinn.securitytoken.service.ISecurityService;
import io.github.osinn.securitytoken.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;
import java.util.Objects;


/**
 * 自定义访问决策(code认证不会进来，使用默认的认证)
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

    private IApiAuthService apiAuthService;

    private AuthType authType;

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(SecurityStorage securityStorage,
                                       ISecurityService securityService,
                                       IApiAuthService apiAuthService,
                                       AuthType authType) {
        this.securityStorage = securityStorage;
        this.securityService = securityService;
        this.apiAuthService = apiAuthService;
        this.authType = authType;
    }

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {

        if (AuthType.OFF.equals(authType)) {
            // 权限认证关闭状态¸不需要认证权限，放行
            return;
        }

        // 当系统没有配置权限资源时直接放行
        if (CollUtil.isEmpty(configAttributes)) {
            return;
        }

        FilterInvocation filterInvocation = (FilterInvocation) object;
        HttpServletRequest request = filterInvocation.getRequest();

        if (securityStorage.isAnonymousUri(request)) {
            // 放行白名单
            return;
        }

        if (authentication == null) {
            throw new AccessDeniedException("当前访问没有权限");
        }

        OnlineUser onlineUser = (OnlineUser) authentication.getPrincipal();

        Boolean hasRoleAdmin = TokenUtils.hasRoleAdmin(onlineUser.getRoles());
        if (Boolean.TRUE.equals(hasRoleAdmin)) {
            return;
        }

        if (AuthType.SERVICE.equals(authType)) {
            API api = apiAuthService.getServiceApiAnnotation(request);
            APIMethodPermission serviceApiMethodPermissionAnnotation = apiAuthService.getServiceApiMethodPermissionAnnotation(api.service());
            if (serviceApiMethodPermissionAnnotation != null) {
                if (!serviceApiMethodPermissionAnnotation.needPermission()) {
                    return;
                }
            } else if (!api.needPermission()) {
                return;
            }
            // 获取接口访问权限
//            configAttributeList = apiAuthService.getApiConfigAttribute(api, request);
            // 检查是否有权限访问
            apiAuthService.checkAttribute(api, request, authentication.getAuthorities());
        } else if (AuthType.URL.equals(authType)) {
            boolean authority = false;
            if (!configAttributes.isEmpty()) {
                for (ConfigAttribute configAttribute : configAttributes) {
                    //资源比对系统权限
                    String needAuthority = configAttribute.getAttribute();
                    if (Objects.equals(needAuthority, request.getRequestURI())) {
                        authority = true;
                        break;
                    }
                }
            }

            // 请求路径再权限表中，需要认证权限，否则放行
            if (!authority) {
                return;
            }
            /**
             * 后面将删除此方法，直接调用 authentication.getAuthorities()
             */
            apiAuthService.checkResourcePermissionUriPath(request.getRequestURI(), onlineUser.getResourcePermissions(), request);

        }

//        else {
//            /**
//             * 判断是否有权限访问
//             */
//            for (ResourcePermission resourcePermission : onlineUser.getResourcePermissions()) {
//                String needCode = resourcePermission.getPermissionCode();
//                if (needCode != null) {
//                    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//                    for (GrantedAuthority authority : authorities) {
//                        if (authority.getAuthority().equals(needCode)) {
//                            return;
//                        }
//                    }
//                }
//            }
//            request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "当前访问没有权限");
//            throw new AccessDeniedException("当前访问没有权限");
//        }

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