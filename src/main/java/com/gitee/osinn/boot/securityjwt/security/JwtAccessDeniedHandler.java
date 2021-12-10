package com.gitee.osinn.boot.securityjwt.security;

import com.gitee.osinn.boot.securityjwt.exception.SecurityJwtException;
import com.gitee.osinn.boot.securityjwt.starter.SecurityJwtProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import com.gitee.osinn.boot.securityjwt.enums.JwtHttpStatus;
import com.gitee.osinn.boot.securityjwt.utils.ResponseUtils;

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

        // AccessDeniedHandler中只有对页面请求的处理，而没有对Ajax的处理。AJAX请求,使用response发送403
//        if (isAjaxRequest(request)) {
//            response.sendError(JwtHttpStatus.SC_FORBIDDEN.getCode(), JwtHttpStatus.SC_FORBIDDEN.getMessage());
//        } else if (!response.isCommitted()) {
//            // 非AJAX请求，跳转系统默认的403错误界面，在web.xml中配置
//            response.sendError(HttpServletResponse.SC_FORBIDDEN,
//                    accessDeniedException.getMessage());
//        }
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

    /**
     * 判断是否为ajax请求
     */
    private boolean isAjaxRequest(HttpServletRequest request) {
        if (request.getHeader("accept").indexOf("application/json") > -1 ||
                (request.getHeader("X-Requested-With") != null &&
                        request.getHeader("X-Requested-With").equals("XMLHttpRequest"))) {
            return true;
        }
        return false;
    }
}
