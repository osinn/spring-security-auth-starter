package io.github.osinn.security.utils;

import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.dto.CustomizeResponseBodyField;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wency_cai
 **/
public class AuthResponseUtils {

    public static CustomizeResponseBodyField customizeResponseBodyField;

    public static void outWriter(int statusCode, String message, String errorMessage, String path, int tokenExpireHttpResponseCode, HttpServletResponse response) throws IOException {
        if (AuthHttpStatus.TOKEN_EXPIRE.getCode() == statusCode) {
            response.setStatus(tokenExpireHttpResponseCode);
        }
        Map<String, Object> jsonObject = new HashMap<>();
        jsonObject.put(customizeResponseBodyField.getMessageField(), message);
        jsonObject.put(customizeResponseBodyField.getErrorField(), errorMessage);
        jsonObject.put(customizeResponseBodyField.getCodeField(), statusCode);
        jsonObject.put("path", path);
        jsonObject.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(JsonMapper.toJsonStr(jsonObject));
    }

    /**
     * 认证失败抛出异常
     *
     * @param e
     * @throws SecurityAuthException
     */
    public static SecurityAuthException loginFailException(AuthenticationException e) {
        AuthHttpStatus authHttpStatus = getAuthHttpStatus(e);
        return new SecurityAuthException(authHttpStatus.getCode(), authHttpStatus.getMessage());
    }

    public static AuthHttpStatus getAuthHttpStatus(AccessDeniedException accessDeniedException) {
        return AuthHttpStatus.SC_FORBIDDEN;
    }

    public static AuthHttpStatus getAuthHttpStatus(AuthenticationException e) {
        if (e instanceof UsernameNotFoundException || e instanceof BadCredentialsException || e instanceof AuthenticationCredentialsNotFoundException) {
            return AuthHttpStatus.TOKEN_UNAUTHORIZED;
        } else if (e instanceof LockedException) {
            return AuthHttpStatus.LOCK_ACCOUNT;
        } else if (e instanceof CredentialsExpiredException) {
            return AuthHttpStatus.CREDENTIALS_EXPIRED;
        } else if (e instanceof AccountExpiredException) {
            return AuthHttpStatus.TOKEN_EXPIRE;
        } else if (e instanceof DisabledException) {
            return AuthHttpStatus.DISABLED_ACCOUNT;
        } else {
            return AuthHttpStatus.LOGIN_FAIL;
        }
    }
}
