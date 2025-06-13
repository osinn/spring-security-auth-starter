package io.github.osinn.security.security;

import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Objects;


/**
 * @author wency_cai
 */
@Slf4j
public class CustomAccessDecisionManager {

    private AuthType authType;

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(AuthType authType) {
        this.authType = authType;
    }

    public boolean decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) throws AccessDeniedException, InsufficientAuthenticationException {

        // 当系统没有配置权限资源时直接放行
        if (CollectionUtils.isEmpty(configAttributes)) {
            return true;
        }

        HttpServletRequest request = (HttpServletRequest) object;

        if (authentication == null) {
            throw new AccessDeniedException("当前没有访问权限");
        }

        if (authentication.getPrincipal() instanceof OnlineUser onlineUser) {

            Boolean hasRoleAdmin = TokenUtils.hasRoleAdmin(onlineUser.getRoles());

            if (Boolean.TRUE.equals(hasRoleAdmin)) {
                return true;
            }
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
