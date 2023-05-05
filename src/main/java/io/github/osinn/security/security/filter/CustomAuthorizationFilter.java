package io.github.osinn.security.security.filter;

import io.github.osinn.security.security.AccessDecisionAuthorizationManager;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.io.IOException;

/**
 * 自定义权限认证过滤器
 *
 * @author wency_cai
 */
public class CustomAuthorizationFilter extends AuthorizationFilter {

    private boolean observeOncePerRequest = false;

    private boolean filterErrorDispatch = true;

    private boolean filterAsyncDispatch = true;


    private AccessDecisionAuthorizationManager accessDecisionAuthorizationManager;

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    /**
     * Creates an instance.
     *
     * @param authorizationManager the {@link AuthorizationManager} to use
     */
    public CustomAuthorizationFilter(AccessDecisionAuthorizationManager<HttpServletRequest> authorizationManager) {
        super(authorizationManager);
        this.accessDecisionAuthorizationManager = authorizationManager;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (this.observeOncePerRequest && isApplied(request)) {
            chain.doFilter(request, response);
            return;
        }

        if (skipDispatch(request)) {
            chain.doFilter(request, response);
            return;
        }

        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
        try {
            AuthorizationDecision decision = accessDecisionAuthorizationManager.check(this::getAuthentication, request);
            if (decision != null && !decision.isGranted()) {
                throw new AccessDeniedException("Access Denied");
            }
            chain.doFilter(request, response);
        } finally {
            request.removeAttribute(alreadyFilteredAttributeName);
        }
    }

    private Authentication getAuthentication() {
        Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
        if (authentication == null) {
            throw new AuthenticationCredentialsNotFoundException(
                    "An Authentication object was not found in the SecurityContext");
        }
        return authentication;
    }

    private boolean skipDispatch(HttpServletRequest request) {
        if (DispatcherType.ERROR.equals(request.getDispatcherType()) && !this.filterErrorDispatch) {
            return true;
        }
        return DispatcherType.ASYNC.equals(request.getDispatcherType()) && !this.filterAsyncDispatch;
    }

    private String getAlreadyFilteredAttributeName() {
        String name = getFilterName();
        if (name == null) {
            name = getClass().getName();
        }
        return name + ".APPLIED";
    }

    private boolean isApplied(HttpServletRequest request) {
        return request.getAttribute(getAlreadyFilteredAttributeName()) != null;
    }
}
