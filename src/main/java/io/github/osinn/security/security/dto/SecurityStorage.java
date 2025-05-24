package io.github.osinn.security.security.dto;

import lombok.Data;
import org.springframework.http.HttpMethod;
import org.springframework.util.AntPathMatcher;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * 存储
 *
 * @author wency_cai
 */
@Data
public class SecurityStorage {

    /**
     * 白名单
     */
    private Set<String> permissionAnonymousUrlList;

    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 判断是否是白名单
     *
     * @param request
     * @return
     */
    public boolean isAnonymousUri(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        // 放行白名单
        for (String url : permissionAnonymousUrlList) {
            boolean match = antPathMatcher.match(url, requestUri);
            if (match || requestUri.equals(url)) {
                return true;
            }
        }

        //OPTIONS请求直接放行
        if (request.getMethod().equals(HttpMethod.OPTIONS.toString())) {
            return true;
        }

        return false;
    }
}
