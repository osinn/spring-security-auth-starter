package io.github.osinn.security.utils;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.starter.SecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * 描述
 *
 * @author wency_cai
 */
@Slf4j
public class IpRangeCheckerUtils {

    /**
     * 检查IP是否在指定IP段范围内
     *
     * @param ip   要检查的IP
     * @param cidr IP段 如 "192.168.1.0/24"
     * @return 是否匹配
     */
    public static boolean isInRange(String ip, String cidr) {
        String[] parts = cidr.split("/");
        String network = parts[0];
        int prefix;

        if (parts.length < 2) {
            prefix = 0;
        } else {
            prefix = Integer.parseInt(parts[1]);
        }

        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            InetAddress networkAddress = InetAddress.getByName(network);

            byte[] ipBytes = ipAddress.getAddress();
            byte[] networkBytes = networkAddress.getAddress();

            // 比较IP地址和网络地址的前prefix位
            if (ipBytes.length != networkBytes.length) {
                return false;
            }

            int i = 0;
            while (prefix > 0 && i < ipBytes.length) {
                int mask = prefix >= 8 ? 0xff : (0xff << (8 - prefix));
                if ((ipBytes[i] & mask) != (networkBytes[i] & mask)) {
                    return false;
                }
                i++;
                prefix -= 8;
            }

            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * 检查IP是否在多个IP段中的任意一个
     *
     * @param ip    要检查的IP
     * @param cidrs IP段数组
     * @return 是否匹配任意一个
     */
    public static boolean isInAnyRange(String ip, String... cidrs) {
        for (String cidr : cidrs) {
            if (isInRange(ip, cidr)) {
                return true;
            }
        }
        return false;
    }

    public static boolean checkInterceptor(HttpServletRequest request, SecurityProperties.IpIntercept ipIntercept) {
        Set<String> allow = RedisUtils.get(AuthConstant.CACHE_IP_INTERCEPT_ALLOW);
        Set<String> deny = RedisUtils.get(AuthConstant.CACHE_IP_INTERCEPT_DENY);

        if (StrUtils.isEmpty(allow) && StrUtils.isEmpty(deny)) {
            allow = ipIntercept.getAllow();
            deny = ipIntercept.getDeny();
        }

        if (StrUtils.isEmpty(allow) && StrUtils.isEmpty(deny)) {
            return true;
        }

        String ip = StrUtils.getIp(request);
        if (isInAnyRange(ip, allow.toArray(new String[0]))) {
            return true;
        }

        if (isInAnyRange(ip, deny.toArray(new String[0]))) {
            log.warn("[{}]被拒绝访问", ip);
            return false;
        }
        return true;
    }
}
