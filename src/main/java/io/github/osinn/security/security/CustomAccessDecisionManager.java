package io.github.osinn.security.security;

import cn.hutool.core.collection.CollUtil;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Collection;
import java.util.Objects;


/**
 * 使用 @PreAuthorize("hasAnyAuthority('xxx:xxx:xxx')") 访问权限控制会触发此认证校验
 *
 * @author wency_cai
 */
@Slf4j
public class CustomAccessDecisionManager {


    /**
     * 白名单
     */
    private SecurityStorage securityStorage;

    private AuthType authType;

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(SecurityStorage securityStorage,
                                       AuthType authType) {
        this.securityStorage = securityStorage;
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

        if (AuthType.URL.equals(authType)) {
            if (!configAttributes.isEmpty()) {
                // 请求路径再权限表中，需要认证权限，否则放行
                boolean authority = false;
                for (ConfigAttribute configAttribute : configAttributes) {
                    //资源比对系统权限
                    String needAuthority = configAttribute.getAttribute();
                    if (Objects.equals(needAuthority, request.getRequestURI())) {
                        authority = true;
                        break;
                    }
                }

                return authority;
            }

        }

        return true;
    }


}
