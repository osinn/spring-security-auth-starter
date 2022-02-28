package com.gitee.osinn.boot.securityjwt.security.filter.request;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * xss过滤器且处理request.getInputStream()只能读取一次问题
 *
 * @author wency_cai
 */
public class MyRequestFilter implements Filter {

    private final boolean enableXss;

    public MyRequestFilter(boolean enableXss) {
        this.enableXss = enableXss;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        filterChain.doFilter(new MyHttpServletRequestWrapper(request, enableXss), servletResponse);
    }
}
