package io.github.osinn.security.utils;

import io.github.osinn.security.constants.AuthConstant;
import eu.bitwalker.useragentutils.Browser;
import eu.bitwalker.useragentutils.UserAgent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;

import jakarta.servlet.http.HttpServletRequest;

import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

/**
 * 字符串工具类
 *
 * @author wency_cai
 **/
@Slf4j
public class StrUtils {
    /**
     * 获取ip地址
     */
    public static String getIp(HttpServletRequest request) {
        String ip = request.getHeader(AuthConstant.X_FORWARDED_FOR);
        if (ip == null || ip.length() == 0 || AuthConstant.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader(AuthConstant.PROXY_CLIENT_IP);
        }
        if (ip == null || ip.length() == 0 || AuthConstant.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader(AuthConstant.WL_PROXY_CLIENT_IP);
        }
        if (ip == null || ip.length() == 0 || AuthConstant.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        String comma = ",";
        if (ip.contains(comma)) {
            ip = ip.split(",")[0];
        }
        if (AuthConstant.LOCALHOST.equals(ip)) {
            // 获取本机真正的ip地址
            try {
                ip = InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e) {
                log.error(e.getMessage(), e);
            }
        }
        return ip;
    }

    public static String getBrowser(HttpServletRequest request) {
        UserAgent userAgent = UserAgent.parseUserAgentString(request.getHeader(AuthConstant.UA));
        Browser browser = userAgent.getBrowser();
        return browser.getName();
    }

    /**
     * 判断是否不为空
     *
     * @param obj 要判断空的对象
     * @return 空返回true, 否则返回false
     */
    public static boolean isEmpty(@Nullable Object obj) {
        if (obj == null) {
            return true;
        }

        if (obj instanceof Optional) {
            return !((Optional<?>) obj).isPresent();
        }
        if (obj instanceof CharSequence) {
            return ((CharSequence) obj).length() == 0;
        }
        if (obj.getClass().isArray()) {
            return Array.getLength(obj) == 0;
        }
        if (obj instanceof Collection) {
            return ((Collection<?>) obj).isEmpty();
        }
        if (obj instanceof Map) {
            return ((Map<?, ?>) obj).isEmpty();
        }
        return false;
    }


}
