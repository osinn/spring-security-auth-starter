package io.github.osinn.security.utils;

import io.github.osinn.security.constants.JwtConstant;
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
 * @author wency_cai
 * @description: 字符串工具类
 **/
@Slf4j
public class StrUtils {
    /**
     * 获取ip地址
     */
    public static String getIp(HttpServletRequest request) {
        String ip = request.getHeader(JwtConstant.X_FORWARDED_FOR);
        if (ip == null || ip.length() == 0 || JwtConstant.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader(JwtConstant.PROXY_CLIENT_IP);
        }
        if (ip == null || ip.length() == 0 || JwtConstant.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader(JwtConstant.WL_PROXY_CLIENT_IP);
        }
        if (ip == null || ip.length() == 0 || JwtConstant.UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        String comma = ",";
        if (ip.contains(comma)) {
            ip = ip.split(",")[0];
        }
        if (JwtConstant.LOCALHOST.equals(ip)) {
            // 获取本机真正的ip地址
            try {
                ip = InetAddress.getLocalHost().getHostAddress();
            } catch (UnknownHostException e) {
                log.error(e.getMessage(), e);
            }
        }
        return ip;
    }


//    public static String getCityInfo(String ip, String ip2regionPath) {
//        DbSearcher searcher = null;
//        ClassPathResource resource = new ClassPathResource(ip2regionPath);
//        try {
//            InputStream inputStream = resource.getInputStream();
//            DbConfig config = new DbConfig();
//            int nRead;
//            byte[] data = new byte[1024];
//            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
//            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
//                buffer.write(data, 0, nRead);
//            }
//            buffer.flush();
//            byte[] in2b = buffer.toByteArray();
////            URL resource = StrUtils.class.getClassLoader().getResource(ip2regionPath);
////            String path = resource.getPath();
////            searcher = new DbSearcher(config, path);
//            searcher = new DbSearcher(config, in2b);
//            Method method;
//            method = searcher.getClass().getMethod("memorySearch", String.class);
//            ;
//            DataBlock dataBlock;
//            dataBlock = (DataBlock) method.invoke(searcher, ip);
//            String address = dataBlock.getRegion().replace("0|", "");
//            char symbol = '|';
//            if (address.charAt(address.length() - 1) == symbol) {
//                address = address.substring(0, address.length() - 1);
//            }
//            return JwtConstant.REGION.equals(address) ? "内网IP" : address;
//        } catch (Exception e) {
//            log.debug(e.getMessage(), e);
//        } finally {
//            if (searcher != null) {
//                try {
//                    searcher.close();
//                } catch (IOException ignored) {
//                    log.debug(ignored.getMessage(), ignored);
//                }
//            }
//
//        }
//        return "";
//    }

    public static String getBrowser(HttpServletRequest request) {
        UserAgent userAgent = UserAgent.parseUserAgentString(request.getHeader(JwtConstant.UA));
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
