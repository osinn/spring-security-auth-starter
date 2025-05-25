package io.github.osinn.security.utils;

import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.dto.CustomizeResponseBodyField;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wency_cai
 **/
public class ResponseUtils {

    public static CustomizeResponseBodyField customizeResponseBodyField;

    public static void outWriter(int statusCode, String message, String errorMessage, String path, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (AuthHttpStatus.TOKEN_EXPIRE.getCode() == statusCode) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
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
    public static void loginFailThrows(AuthenticationException e) throws SecurityAuthException {
        String message;
        int statusCode;
        if (e instanceof UsernameNotFoundException || e instanceof BadCredentialsException) {
            message = AuthHttpStatus.TOKEN_UNAUTHORIZED.getMessage();
            statusCode = AuthHttpStatus.TOKEN_UNAUTHORIZED.getCode();
        } else if (e instanceof LockedException) {
            message = AuthHttpStatus.LOCK_ACCOUNT.getMessage();
            statusCode = AuthHttpStatus.LOCK_ACCOUNT.getCode();
        } else if (e instanceof CredentialsExpiredException) {
            message = AuthHttpStatus.CREDENTIALS_EXPIRED.getMessage();
            statusCode = AuthHttpStatus.CREDENTIALS_EXPIRED.getCode();
        } else if (e instanceof AccountExpiredException) {
            message = AuthHttpStatus.TOKEN_EXPIRE.getMessage();
            statusCode = AuthHttpStatus.TOKEN_EXPIRE.getCode();
        } else if (e instanceof DisabledException) {
            message = AuthHttpStatus.DISABLED_ACCOUNT.getMessage();
            statusCode = AuthHttpStatus.DISABLED_ACCOUNT.getCode();
        } else {
            message = AuthHttpStatus.LOGIN_FAIL.getMessage();
            statusCode = AuthHttpStatus.LOGIN_FAIL.getCode();
        }
        throw new SecurityAuthException(statusCode, message);
    }
}
