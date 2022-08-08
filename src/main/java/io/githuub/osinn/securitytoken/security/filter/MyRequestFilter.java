package io.githuub.osinn.securitytoken.security.filter;

import io.githuub.osinn.securitytoken.enums.AuthType;
import io.githuub.osinn.securitytoken.security.filter.request.MyHttpServletRequestJsonBodyWrapper;
import io.githuub.osinn.securitytoken.security.filter.request.MyXssHttpServletRequestWrapper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 请求过滤器
 *
 * @author wency_cai
 */
public class MyRequestFilter implements Filter {

    private final static String OPTIONS = "OPTIONS";

    private final boolean enableCors;
    private final boolean enableXss;
    private final AuthType authType;

    public MyRequestFilter(boolean enableCors, boolean enableXss, AuthType authType) {
        this.enableCors = enableCors;
        this.enableXss = enableXss;
        this.authType = authType;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        if(enableCors) {
            //解决跨域的问题
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Credentials", "true");
            response.setHeader("Access-Control-Allow-Headers", "*");
            response.setHeader("Access-Control-Allow-Methods", "*");
            response.setHeader("Access-Control-Max-Age", "18000");
        }

        // 跨域会发起预校验的OPTIONS请求，所以OPTIONS预校验请求，直接跳过
        if (OPTIONS.equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            if (AuthType.SERVICE.equals(authType)) {
                filterChain.doFilter(new MyHttpServletRequestJsonBodyWrapper(request, enableXss), servletResponse);
            } else {
                filterChain.doFilter(new MyXssHttpServletRequestWrapper(request, enableXss), servletResponse);
            }
        }
    }

}