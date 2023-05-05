package io.github.osinn.security.security.filter;

import cn.hutool.core.io.IoUtil;
import cn.hutool.json.JSONUtil;
import com.google.common.base.Charsets;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.filter.request.MyHttpServletRequestJsonBodyWrapper;
import io.github.osinn.security.security.filter.request.MyXssHttpServletRequestWrapper;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

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
            if (AuthType.SERVICE.equals(authType)) {
                filterChain.doFilter(new MyHttpServletRequestJsonBodyWrapper(request, enableXss), servletResponse);
            } else {
                filterChain.doFilter(new MyXssHttpServletRequestWrapper(request, enableXss), servletResponse);
            }
        }
    }

    /**
     * 打印请求参数
     */
    private void logRequestParameter(HttpServletRequest httpServletRequest) {
        try {
            String parameter = "";
            if (httpServletRequest.getContentType() == null || !httpServletRequest.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)) {
                Map<String, String[]> parameterMaps = httpServletRequest.getParameterMap();
                Map<String, Object> parameterMap = new HashMap<>();
                parameterMaps.forEach((key, values) -> {
                    if (values != null && values.length > 1) {
                        parameterMap.put(key, values);
                    } else if (values != null && values.length == 1) {
                        parameterMap.put(key, values[0]);
                    }
                });
                parameter = JSONUtil.toJsonStr(parameterMap);
            } else {
                try {
                    parameter = new String(IoUtil.readBytes(httpServletRequest.getInputStream()), Charsets.UTF_8);
                } catch (Exception e) {
                    log.debug("security 获取服务名称-HttpServletRequest 尝试解析表单请求json数据失败：" + e.getMessage(), e);
                }
            }
            log.info("security 请求参数 ===>>> {}", parameter);
        } catch (Exception e) {
            log.info("security打印请求参数异常");
        }


    }
}