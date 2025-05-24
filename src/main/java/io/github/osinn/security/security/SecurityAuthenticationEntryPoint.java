package io.github.osinn.security.security;

import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.starter.SecurityProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.utils.ResponseUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 认证失败调用
 *
 * @author wency_cai
 */
public class SecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final SecurityProperties securityProperties;

    public SecurityAuthenticationEntryPoint(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 当用户尝试访问安全的REST资源而不提供任何凭据时，将调用此方法发送4001 响应
        String message = (String) request.getAttribute(AuthHttpStatus.TOKEN_EXPIRE.name());
        int statusCode;
        if (message == null) {
            statusCode = AuthHttpStatus.TOKEN_UNAUTHORIZED.getCode();
        } else {
            statusCode = AuthHttpStatus.TOKEN_EXPIRE.getCode();
        }

        if (securityProperties.isAuthFailThrows()) {
            throw new SecurityAuthException(statusCode, authException.getMessage());
        } else {
            response.setStatus(HttpStatus.OK.value());
            String  path = request.getRequestURI();
            Throwable cause = authException.getCause();
            if (cause instanceof SecurityAuthException securityAuthException) {
                message = securityAuthException.getMessage();
                statusCode = securityAuthException.getStatus();
            }
            ResponseUtils.outWriter(statusCode, message, authException.getMessage(), path, request, response);
        }

    }

}
