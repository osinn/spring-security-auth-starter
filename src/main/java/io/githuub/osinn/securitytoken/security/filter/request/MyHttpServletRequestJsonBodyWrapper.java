package io.githuub.osinn.securitytoken.security.filter.request;

import io.githuub.osinn.securitytoken.constants.JwtConstant;
import com.google.common.base.Charsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 重写HttpServletRequest解决json格式请求，重复读取流问题
 *
 * @author wency_cai
 */
@Slf4j
public class MyHttpServletRequestJsonBodyWrapper extends MyXssHttpServletRequestWrapper {

    private byte[] content;


    public MyHttpServletRequestJsonBodyWrapper(HttpServletRequest request, boolean enableXss) {
        super(request, enableXss);
        if (MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType())) {
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream(), Charsets.UTF_8))) {
                String line = "";
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
            this.content = sb.toString().getBytes(Charsets.UTF_8);
        }
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (this.content == null || !super.getHeader(JwtConstant.CONTENT_TYPE).equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)) {
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

}