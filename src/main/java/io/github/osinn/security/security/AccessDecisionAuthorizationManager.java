package io.github.osinn.security.security;

import org.springframework.security.access.AccessDeniedException;
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


    public AccessDecisionAuthorizationManager(CustomAccessDecisionManager accessDecisionManager) {
        this.accessDecisionManager = accessDecisionManager;
    }


    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest httpServletRequest) {
        try {
            // 检查用户是否拥有访问权限
            boolean decide = this.accessDecisionManager.decide(authentication.get(), httpServletRequest);
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
