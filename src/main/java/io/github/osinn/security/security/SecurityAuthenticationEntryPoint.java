package io.github.osinn.security.security;

import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.starter.SecurityProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import io.github.osinn.security.utils.AuthResponseUtils;

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
        if (securityProperties.isAuthFailThrows()) {
            throw authException;
        } else {
            SecurityAuthException securityAuthentication = AuthResponseUtils.loginFailException(authException);
            response.setStatus(HttpStatus.OK.value());
            String path = request.getRequestURI();
            String message = securityAuthentication.getMessage();
            Integer statusCode = securityAuthentication.getStatus();
            AuthResponseUtils.outWriter(statusCode, message, authException.getMessage(), path, securityProperties.getTokenExpireHttpResponseCode(), response);
        }

    }

}
