package io.github.osinn.security.security;


import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.exception.SecurityJwtException;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.starter.SecurityJwtProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import io.github.osinn.security.enums.JwtHttpStatus;
import io.github.osinn.security.utils.ResponseUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 认证失败调用
 *
 * @author wency_cai
 */
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Autowired
    private ISecurityService securityService;

    private SecurityJwtProperties securityJwtProperties;

    public JwtAuthenticationEntryPoint(SecurityJwtProperties securityJwtProperties) {
        this.securityJwtProperties = securityJwtProperties;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 当用户尝试访问安全的REST资源而不提供任何凭据时，将调用此方法发送4001 响应
        String message = (String) request.getAttribute(JwtHttpStatus.TOKEN_EXPIRE.name());
        int statusCode;
        if (message == null) {
            statusCode = JwtHttpStatus.TOKEN_UNAUTHORIZED.getCode();
        } else {
            statusCode = JwtHttpStatus.TOKEN_EXPIRE.getCode();
        }

        if (securityJwtProperties.isAuthFailThrows()) {
            throw new SecurityJwtException(statusCode, authException.getMessage());
        } else {
            response.setStatus(HttpStatus.OK.value());
            String path;
            if (AuthType.SERVICE.equals(securityJwtProperties.getAuthType())) {
                path = securityService.getServiceName(request);
            } else {
                path = request.getRequestURI();
            }
            Throwable cause = authException.getCause();
            if (cause instanceof SecurityJwtException) {
                SecurityJwtException signatureJwtException = (SecurityJwtException) cause;
                message = signatureJwtException.getMessage();
                statusCode = signatureJwtException.getStatus();
            }
            ResponseUtils.outWriter(statusCode, message, authException.getMessage(), path, request, response);
        }

    }

}
