package io.github.osinn.security.security.filter.request;

import io.github.osinn.security.utils.StrUtils;
import lombok.extern.slf4j.Slf4j;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import static org.springframework.web.util.HtmlUtils.htmlEscape;

/**
 * xss 处理,流不可重复读取
 *
 * @author wency_cai
 */
@Slf4j
public class MyXssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    public MyXssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public String getQueryString() {
        String value = super.getQueryString();
        if (StrUtils.isEmpty(value)) {
            return value;
        }
        return xssHtmlEscape(value);
    }

    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        if (StrUtils.isEmpty(value)) {
            return value;
        }
        return xssHtmlEscape(value);
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (StrUtils.isEmpty(values)) {
            return values;
        }
        int length = values.length;
        String[] escapeValues = new String[length];
        for (int i = 0; i < length; i++) {
            String value = values[i];
            if (StrUtils.isEmpty(value)) {
                escapeValues[i] = value;
            } else {
                escapeValues[i] = xssHtmlEscape(value);
            }
        }
        return escapeValues;
    }

    private String xssHtmlEscape(String value) {
        return htmlEscape(value);
    }

}
