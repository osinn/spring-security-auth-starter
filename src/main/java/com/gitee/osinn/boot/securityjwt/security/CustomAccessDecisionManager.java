package com.gitee.osinn.boot.securityjwt.security;

import com.gitee.osinn.boot.securityjwt.annotation.API;
import com.gitee.osinn.boot.securityjwt.annotation.APIMethodPermission;
import com.gitee.osinn.boot.securityjwt.enums.AuthType;
import com.gitee.osinn.boot.securityjwt.security.dto.SecurityStorage;
import com.gitee.osinn.boot.securityjwt.service.IApiAuthService;
import com.gitee.osinn.boot.securityjwt.service.ISecurityService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
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

        FilterInvocation filterInvocation = (FilterInvocation) object;
        HttpServletRequest request = filterInvocation.getRequest();
        List<ConfigAttribute> configAttributeList;

        if (securityStorage.isAnonymousUri(request)) {
            // 放行白名单
            return;
        }

        if (authentication == null) {
            throw new AccessDeniedException("当前访问没有权限");
        }

        if (AuthType.SERVICE.equals(authType)) {
            API api = apiAuthService.getServiceApiAnnotation(request);
            APIMethodPermission serviceApiMethodPermissionAnnotation = apiAuthService.getServiceApiMethodPermissionAnnotation(request);
            if(serviceApiMethodPermissionAnnotation != null) {
               if(!serviceApiMethodPermissionAnnotation.needPermission()) {
                   return;
               }
            } else if (!api.needPermission()) {
                return;
            }
            // 获取接口访问权限
//            configAttributeList = apiAuthService.getApiConfigAttribute(api, request);
            // 检查是否有权限访问
            apiAuthService.checkAttribute(api, request, authentication.getAuthorities());
        } else {

            /**
             * 后面将删除此方法，直接调用 authentication.getAuthorities()
             */
            configAttributeList = apiAuthService.getConfigAttribute(request.getRequestURI(), request);

            /**
             * 判断是否有权限访问
             */
            for (ConfigAttribute attribute : configAttributeList) {
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