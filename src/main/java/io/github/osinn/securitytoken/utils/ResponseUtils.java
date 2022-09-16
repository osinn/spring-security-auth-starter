package io.github.osinn.securitytoken.utils;

import cn.hutool.json.JSONConfig;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.osinn.securitytoken.enums.JwtHttpStatus;
import io.github.osinn.securitytoken.exception.SecurityJwtException;
import io.github.osinn.securitytoken.security.dto.CustomizeResponseBodyField;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * @author wency_cai
 **/
public class ResponseUtils {

    public static CustomizeResponseBodyField customizeResponseBodyField;

    public static void outWriter(int statusCode, String message, String errorMessage, String path, HttpServletRequest request, HttpServletResponse response) throws IOException {
        JSONObject jsonObject = JSONUtil.createObj(JSONConfig.create().setIgnoreNullValue(false));
        jsonObject.set(customizeResponseBodyField.getMessageField(), message);
        jsonObject.set(customizeResponseBodyField.getErrorField(), errorMessage);
        jsonObject.set(customizeResponseBodyField.getCodeField(), statusCode);
        jsonObject.set("path", path);
        jsonObject.set("timestamp", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(JSONUtil.toJsonStr(jsonObject));
    }

    /**
     * 认证失败抛出异常
     *
     * @param e
     * @throws SecurityJwtException
     */
    public static void loginFailThrows(AuthenticationException e) throws SecurityJwtException {
        String message;
        int statusCode;
        if (e instanceof UsernameNotFoundException || e instanceof BadCredentialsException) {
            message = JwtHttpStatus.TOKEN_UNAUTHORIZED.getMessage();
            statusCode = JwtHttpStatus.TOKEN_UNAUTHORIZED.getCode();
        } else if (e instanceof LockedException) {
            message = JwtHttpStatus.LOCK_ACCOUNT.getMessage();
            statusCode = JwtHttpStatus.LOCK_ACCOUNT.getCode();
        } else if (e instanceof CredentialsExpiredException) {
            message = JwtHttpStatus.CREDENTIALS_EXPIRED.getMessage();
            statusCode = JwtHttpStatus.CREDENTIALS_EXPIRED.getCode();
        } else if (e instanceof AccountExpiredException) {
            message = JwtHttpStatus.TOKEN_EXPIRE.getMessage();
            statusCode = JwtHttpStatus.TOKEN_EXPIRE.getCode();
        } else if (e instanceof DisabledException) {
            message = JwtHttpStatus.DISABLED_ACCOUNT.getMessage();
            statusCode = JwtHttpStatus.DISABLED_ACCOUNT.getCode();
        } else {
            message = JwtHttpStatus.LOGIN_FAIL.getMessage();
            statusCode = JwtHttpStatus.LOGIN_FAIL.getCode();
        }
        throw new SecurityJwtException(statusCode, message);
    }
}
