package io.github.osinn.security.utils;

import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.starter.SecurityProperties;
import lombok.Data;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Set;

/**
 * 存储
 *
 * @author wency_cai
 */
@Data
public class PermissionUtils {

    /**
     * 白名单
     */
    private static Set<String> permissionAnonymousUrlList;

    private static AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 判断是否是白名单
     *
     * @param request
     * @return
     */
    public static boolean isAnonymousUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        // 放行白名单
        for (String url : permissionAnonymousUrlList) {
            boolean match = antPathMatcher.match(url, requestUri);
            if (match || requestUri.equals(url)) {
                return true;
            }
        }

        //OPTIONS请求直接放行
        return request.getMethod().equals(HttpMethod.OPTIONS.toString());
    }

    public static boolean isAnonymous(SecurityProperties securityProperties) {
        return isAnonymous(securityProperties, null);
    }

    public static boolean isAnonymous(SecurityProperties securityProperties, HttpServletRequest request) {
        if (AuthType.OFF.equals(securityProperties.getAuthType())) {
            // 权限认证关闭状态¸不需要认证权限，放行
            return true;
        }

        if (request == null) {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            Assert.notNull(attributes, "RequestContextHolder.getRequestAttributes can't be NULL");
            request = attributes.getRequest();
        }

        if (isAnonymousUri(request)) {
            // 放行白名单
            return true;
        }

        String token = TokenUtils.getToken();
        // 白名单token放行
        return token != null && securityProperties.getIgnoringToken().contains(securityProperties.getTokenStartWith() + token);
    }

    public static void setPermissionAnonymousUrlList(Set<String> anonymousUrls) {
        permissionAnonymousUrlList = anonymousUrls;
    }
}
