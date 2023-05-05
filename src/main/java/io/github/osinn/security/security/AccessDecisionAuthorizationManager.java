package io.github.osinn.security.security;

import io.github.osinn.security.enums.AuthType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import java.util.Collection;
import java.util.function.Supplier;

/**
 * 接口鉴权-检查是否拥有访问接口权限
 *
 * @author wency_cai
 */
public class AccessDecisionAuthorizationManager<HttpServletRequest> implements AuthorizationManager<HttpServletRequest> {

    private final CustomAccessDecisionManager accessDecisionManager;

    private CustomSecurityMetadataSource securityMetadataSource;


    public AccessDecisionAuthorizationManager(CustomAccessDecisionManager accessDecisionManager,
                                              CustomSecurityMetadataSource securityMetadataSource) {
        this.accessDecisionManager = accessDecisionManager;
        this.securityMetadataSource = securityMetadataSource;
    }


    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest httpServletRequest) {
        try {
            // 获取系统安全数据源
            Collection<ConfigAttribute> attributes = this.securityMetadataSource.getAttributes(httpServletRequest);
            // 检查用户是否拥有访问权限
            boolean decide = this.accessDecisionManager.decide(authentication.get(), httpServletRequest, attributes);
            return new AuthorizationDecision(decide);
        } catch (AccessDeniedException ex) {
            return new AuthorizationDecision(false);
        }
    }

    @Override
    public void verify(Supplier<Authentication> authentication, HttpServletRequest httpServletRequest) {
        AuthorizationDecision decision = check(authentication, httpServletRequest);
        if (decision != null && !decision.isGranted()) {
            throw new AccessDeniedException("Access Denied");
        }
    }

}