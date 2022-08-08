package io.githuub.osinn.securitytoken.security;

import io.githuub.osinn.securitytoken.exception.SecurityJwtException;
import io.githuub.osinn.securitytoken.starter.SecurityJwtProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import io.githuub.osinn.securitytoken.enums.JwtHttpStatus;
import io.githuub.osinn.securitytoken.utils.ResponseUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 权限不足调用
 *
 * @author wency_cai
 */
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private SecurityJwtProperties securityJwtProperties;

    public JwtAccessDeniedHandler(SecurityJwtProperties securityJwtProperties) {
        this.securityJwtProperties = securityJwtProperties;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {

        String accessDecisionMenuName = (String)request.getAttribute("accessDecisionMenuName");
        accessDecisionMenuName = accessDecisionMenuName != null ? accessDecisionMenuName : "";
        int statusCode = JwtHttpStatus.SC_FORBIDDEN.getCode();
        String tokenError = accessDecisionMenuName + JwtHttpStatus.SC_FORBIDDEN.getMessage();
        if (securityJwtProperties.isAuthFailThrows()) {
            throw new SecurityJwtException(statusCode, tokenError);
        } else {
            response.setStatus(HttpStatus.OK.value());
            ResponseUtils.outWriter(statusCode, tokenError, accessDeniedException.getMessage(), request, response);
        }
    }

}
