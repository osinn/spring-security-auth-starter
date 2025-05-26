package io.github.osinn.security.security.filter.request;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.apache.tomcat.util.http.fileupload.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;


/**
 * XSS防护请求包装类
 *
 * @author wency_cai
 */
public class MyXssHttpServletRequestWrapper extends HttpServletRequestWrapper {

    public MyXssHttpServletRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    private String cleanXss(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        value = value.replaceAll("<script>", "#script#");
        value = value.replaceAll("</script>", "#/script#");
        value = value.replaceAll("<script(.*?)>", "#script#");
        value = value.replaceAll("eval\\((.*?)\\)", "#eval#");
        value = value.replaceAll("expression\\((.*?)\\)", "#expression#");
        value = value.replaceAll("javascript:", "#javascript#");
        value = value.replaceAll("vbscript:", "#vbscript#");
        value = value.replaceAll("onload(.*?)=", "#onload#");
        return value;
    }


    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        return cleanXss(value);
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values == null) {
            return null;
        }
        String[] encodedValues = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            encodedValues[i] = cleanXss(values[i]);
        }
        return encodedValues;
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        Map<String, String[]> parameterMap = super.getParameterMap();
        Map<String, String[]> encodedParameterMap = new HashMap<>();
        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            String[] encodedValues = new String[entry.getValue().length];
            for (int i = 0; i < entry.getValue().length; i++) {
                encodedValues[i] = cleanXss(entry.getValue()[i]);
            }
            encodedParameterMap.put(entry.getKey(), encodedValues);
        }
        return encodedParameterMap;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IOUtils.copy(super.getInputStream(), byteArrayOutputStream);

        String content = byteArrayOutputStream.toString(StandardCharsets.UTF_8);
        if (!content.isEmpty()) {
            content = cleanXss(content);
        }
        return new XssServletInputStream(content.getBytes(StandardCharsets.UTF_8));
    }

    private static class XssServletInputStream extends ServletInputStream {

        private final ByteArrayInputStream buffer;

        public XssServletInputStream(byte[] contents) {
            this.buffer = new ByteArrayInputStream(contents);
        }

        @Override
        public int read() throws IOException {
            return buffer.read();
        }

        @Override
        public boolean isFinished() {
            return buffer.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
            throw new UnsupportedOperationException();
        }
    }
}
