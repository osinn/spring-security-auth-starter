package io.github.osinn.security.utils;

import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.security.dto.AuthRoleInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Arrays;
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
     * 获取全部在线用户
     *
     * @return
     */
    public static List<OnlineUser> getOnlineUserAll() {
        return onlineUserService.getOnlineUserAll();
    }

    /**
     * 根据用户id筛选在线的用户（多端登录，多个token对应一个用户）
     *
     * @param filterUserId
     * @return
     */
    public static List<OnlineUser> getOnlineUserAllByUserId(Object filterUserId) {
        return onlineUserService.getOnlineUserAllByUserId(filterUserId);
    }

    /**
     * 获取当前在线用户
     *
     * @return
     */
    public static OnlineUser getOnlineUserInfo() {
        return onlineUserService.getOnlineUserInfo();
    }

    /**
     * 根据token获取当前在线用户
     *
     * @return
     */
    public static OnlineUser getOnlineUserInfoByToken(String token) {
        return onlineUserService.getOnlineUserInfoByToken(token);
    }

    /**
     * 获取当前在线用户
     *
     * @return 返回在线用户信息
     */
    public static OnlineUser getOnlineUserInfo(HttpServletRequest request) {
        String token = getToken(request);
        return onlineUserService.getOnlineUserInfoByToken(token);
    }

    /**
     * 判断是否包含admin角色
     *
     * @return 如果是超级管理员返回true否则false
     */
    public static Boolean hasRoleAdmin() {
        List<AuthRoleInfo.BaseRoleInfo> roles = getOnlineUserInfo().getRoles();
        return roles != null && roles.stream().anyMatch(item -> item.getRoleCode().equals(securityProperties.getSuperAdminRole()));
    }

    /**
     * 判断是否包含admin角色
     *
     * @return 如果是超级管理员返回true否则false
     */
    public static Boolean hasRoleAdmin(String... roleCodes) {
        return !ObjectUtils.isEmpty(roleCodes) && Arrays.stream(roleCodes).anyMatch(item -> item.equals(securityProperties.getSuperAdminRole()));
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
        return roles.stream().anyMatch(item -> item.getRoleCode().equals(securityProperties.getSuperAdminRole()));
    }

    /**
     * 退出登录
     */
    public static void logout() {
        onlineUserService.logout();
    }

    /**
     * 根据用户id强制退出登录
     *
     * @param ids 用户id
     */
    public static void logoutForcibly(List<?> ids) {
        onlineUserService.logoutForcibly(ids);
    }

    /**
     * 刷新token缓存过期时间
     */
    public static void refreshToken(OnlineUser onlineUser) {
        onlineUserService.refreshToken(onlineUser);
    }

    /**
     * 刷新用户权限
     *
     * @param userId
     */
    public static void refreshUserPermission(Object userId) {
        onlineUserService.refreshUserPermission(userId);
    }

    /**
     * 删除全部缓存，如系统权限权限缓存(不会清理token、登录用户信息)
     */
    public static void deleteCacheAll() {
        onlineUserService.deleteCacheAll();
    }

}
