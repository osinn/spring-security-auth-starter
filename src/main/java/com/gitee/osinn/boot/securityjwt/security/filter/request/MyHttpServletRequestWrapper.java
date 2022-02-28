package com.gitee.osinn.boot.securityjwt.security.filter.request;

import com.gitee.osinn.boot.securityjwt.constants.JwtConstant;
import com.gitee.osinn.boot.securityjwt.utils.StrUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.util.FileCopyUtils;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.springframework.web.util.HtmlUtils.htmlEscape;

/**
 * @author wency_cai
 */
@Slf4j
public class MyHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private byte[] content;

    private final boolean enableXss;

    public MyHttpServletRequestWrapper(HttpServletRequest request, boolean enableXss) {
        super(request);
        this.enableXss = enableXss;
        if (MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType())) {
            try {
                //获取文本数据;
                this.content = FileCopyUtils.copyToByteArray(request.getInputStream());
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        }
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

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (!super.getHeader(JwtConstant.CONTENT_TYPE).equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)) {
            return super.getInputStream();
        } else {
            //根据自己的需要重新指定方法
            ByteArrayInputStream in = new ByteArrayInputStream(this.content);
            return new ServletInputStream() {
                @Override
                public int read() throws IOException {
                    return in.read();
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    return in.read(b, off, len);
                }

                @Override
                public int read(byte[] b) throws IOException {
                    return in.read(b);
                }

                @Override
                public void setReadListener(ReadListener listener) {
                }

                @Override
                public boolean isReady() {
                    return false;
                }

                @Override
                public boolean isFinished() {
                    return false;
                }

                @Override
                public long skip(long n) throws IOException {
                    return in.skip(n);
                }

                @Override
                public void close() throws IOException {
                    in.close();
                }

                @Override
                public synchronized void mark(int readlimit) {
                    in.mark(readlimit);
                }

                @Override
                public synchronized void reset() throws IOException {
                    in.reset();
                }
            };
        }
    }

    private String xssHtmlEscape(String value) {
        if (enableXss) {
            return htmlEscape(value);
        } else {
            return value;
        }
    }

}