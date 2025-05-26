package io.github.osinn.security.security.filter;

import io.github.osinn.security.security.filter.request.XssHttpServletRequestWrapper;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

/**
 * 请求过滤器
 *
 * @author wency_cai
 */
@Slf4j
public class MyRequestFilter implements Filter {

    private final static String OPTIONS = "OPTIONS";

    private final boolean enableCors;
    private final boolean enableXss;

    public MyRequestFilter(boolean enableCors, boolean enableXss) {
        this.enableCors = enableCors;
        this.enableXss = enableXss;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        if (enableCors) {
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
            if (enableXss) {
                filterChain.doFilter(new XssHttpServletRequestWrapper(request), servletResponse);
            } else {
                filterChain.doFilter(request, servletResponse);
            }
        }
    }
}
