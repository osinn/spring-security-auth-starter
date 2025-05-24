package io.github.osinn.security.utils;

import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.security.dto.AuthRoleInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.UUID;

/**
 * token工具类
 *
 * @author wency_cai
 **/
@Slf4j
@Component
public class TokenUtils {

    private static SecurityProperties securityProperties;
    private static IOnlineUserService onlineUserService;


    public TokenUtils(SecurityProperties securityProperties, IOnlineUserService onlineUserService) {
        TokenUtils.securityProperties = securityProperties;
        TokenUtils.onlineUserService = onlineUserService;
    }

    /**
     * 创建token
     *
     * @return
     */
    public static String createToken() {
        return UUID.randomUUID().toString().replace("-", "").toUpperCase();
    }

    /**
     * 获取token 不包括令牌前缀
     *
     * @return
     */
    public static String getToken() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return null;
        }
        HttpServletRequest request = attributes.getRequest();
        return getToken(request);
    }

    /**
     * 支持从请求头、get请求、post表单JSON数据中获取token
     *
     * @param request
     * @return
     */
    public static String getToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(securityProperties.getHeader());
        if (!StrUtils.isEmpty(bearerToken) && bearerToken.startsWith(securityProperties.getTokenStartWith())) {
            return bearerToken.replace(securityProperties.getTokenStartWith(), "");
        }
        return null;
    }

    /**
     * 获取当前在线用户
     *
     * @return
     */
    public static OnlineUser fetchOnlineUserInfo() {
        return onlineUserService.fetchOnlineUserCompleteInfo();
    }

    /**
     * 根据token获取当前在线用户
     *
     * @return
     */
    public static OnlineUser fetchOnlineUserCompleteInfoByToken(String token) {
        return onlineUserService.fetchOnlineUserCompleteInfoByToken(token);
    }

    /**
     * 判断是否包含admin角色
     *
     * @return 如果是超级管理员返回true否则false
     */
    public static Boolean hasRoleAdmin() {
        List<AuthRoleInfo.BaseRoleInfo> roles = fetchOnlineUserInfo().getRoles();
        return roles != null && roles.stream().anyMatch(item -> item.getRoleCode().equals(AuthConstant.SUPER_ADMIN_ROLE));
    }

    /**
     * 判断是否包含admin角色
     * 角色 entity可以继承AuthRoleInfo.BaseRoleInfo类方便传值
     *
     * @return 如果是超级管理员返回true否则false
     */
    public static Boolean hasRoleAdmin(List<AuthRoleInfo.BaseRoleInfo> roles) {
        if (roles == null || roles.isEmpty()) {
            return false;
        }
        return roles.stream().anyMatch(item -> item.getRoleCode().equals(AuthConstant.SUPER_ADMIN_ROLE));
    }

    /**
     * 退出登录删除token
     */
    public static void deleteToken() {
        onlineUserService.logout();
    }

    /**
     * 刷新token缓存过期时间
     */
    public static void refreshToken(OnlineUser onlineUser) {
        onlineUserService.refreshToken(onlineUser);
    }

    /**
     * 获取当前在线用户
     *
     * @return 返回在线用户信息
     */
    public static OnlineUser fetchOnlineUserCompleteInfo() {
        return onlineUserService.fetchOnlineUserCompleteInfo();
    }

    /**
     * 获取当前在线用户
     *
     * @return 返回在线用户信息
     */
    public static OnlineUser fetchOnlineUserCompleteInfo(HttpServletRequest request) {
        String token = getToken(request);
        return onlineUserService.fetchOnlineUserCompleteInfoByToken(token);
    }

}
