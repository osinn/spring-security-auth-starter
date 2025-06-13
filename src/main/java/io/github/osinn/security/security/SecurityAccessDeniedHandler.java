package io.github.osinn.security.security;

import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.starter.SecurityProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.utils.AuthResponseUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 权限不足调用
 *
 * @author wency_cai
 */
public class SecurityAccessDeniedHandler implements AccessDeniedHandler {

    private final SecurityProperties securityProperties;

    public SecurityAccessDeniedHandler(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {

        String accessDecisionMenuName = (String)request.getAttribute("accessDecisionMenuName");
        accessDecisionMenuName = accessDecisionMenuName != null ? accessDecisionMenuName : "";
        int statusCode = AuthHttpStatus.SC_FORBIDDEN.getCode();
        String tokenError = accessDecisionMenuName + AuthHttpStatus.SC_FORBIDDEN.getMessage();
        if (securityProperties.isAuthFailThrows()) {
            throw new SecurityAuthException(statusCode, tokenError);
        } else {
            response.setStatus(HttpStatus.OK.value());
            String path = request.getRequestURI();
            AuthResponseUtils.outWriter(statusCode, tokenError, accessDeniedException.getMessage(), path, securityProperties.getTokenExpireHttpResponseCode(), response);
        }
    }

}
