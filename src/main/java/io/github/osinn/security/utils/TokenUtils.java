package io.github.osinn.security.utils;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.security.dto.ResourcePermission;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.security.dto.AuthRoleInfo;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ObjectUtils;
import org.springframework.util.PatternMatchUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.util.*;
import java.util.stream.Collectors;

/**
 * token工具类
 *
 * @author wency_cai
 **/
@Slf4j
public class TokenUtils {

    private static SecurityProperties securityProperties;
    private static IOnlineUserService onlineUserService;

    public static void initAfterPropertiesSet(SecurityProperties securityProperties, IOnlineUserService onlineUserService) {
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
        // 从请求头尝试读取token
        String bearerToken = request.getHeader(securityProperties.getTokenName());
        // 如果请求头不存在token，尝试从 Cookie 里面读取
        if (StrUtils.isEmpty(bearerToken)) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (securityProperties.getTokenName().equals(cookie.getName())) {
                        bearerToken = cookie.getValue();
                        break;
                    }
                }
            }
        }
        //  如果请求头、Cookie都不存在token，尝试从 请求体 里面读取
        if (StrUtils.isEmpty(bearerToken)) {
            bearerToken = request.getParameter(securityProperties.getTokenName());
        }
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
     * @throws SecurityAuthException 如果不存在会抛出异常
     */
    public static OnlineUser getOnlineUserInfo() {
        return onlineUserService.getOnlineUserInfo();
    }

    /**
     * 获取当前在线用户
     *
     * @param throwEx 获取不到用户时是否抛出异常
     * @return
     */
    public static OnlineUser getOnlineUser(boolean throwEx) {
        return onlineUserService.getOnlineUser(throwEx);
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

    /**
     * 判断用户是否拥有此角色
     *
     * @param roles 角色字符串
     * @return {boolean}
     */
    public static boolean checkUserRole(String... roles) {
        if (StrUtils.isEmpty(roles)) {
            return false;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        OnlineUser onlineUser = (OnlineUser) authentication.getPrincipal();
        if (onlineUser == null || StrUtils.isEmpty(onlineUser.getRoles())) {
            return false;
        }
        List<AuthRoleInfo.BaseRoleInfo> onlineUserRoles = onlineUser.getRoles();
        if (StrUtils.isEmpty(onlineUserRoles)) {
            return false;
        }
        return Arrays.stream(roles).anyMatch(role -> onlineUserRoles.stream().anyMatch(sysRole -> role.equals(sysRole.getRoleCode())));
    }

    public static boolean checkUserPermission(String... permissions) {
        if (StrUtils.isEmpty(permissions)) {
            return false;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return Arrays.stream(permissions).anyMatch(permission -> authorities.stream().map(GrantedAuthority::getAuthority).filter(StringUtils::hasText)
                .anyMatch(x -> PatternMatchUtils.simpleMatch(permission, x)));
    }

    /**
     * 获取当前用户所有角色编码集合
     */
    public static Set<String> getCurrentUserRoleCodeAll() {
        List<AuthRoleInfo.BaseRoleInfo> roles = getOnlineUserInfo().getRoles();
        // 返回角色编码集合
        return roles == null ? Collections.emptySet() : roles.stream().map(AuthRoleInfo.BaseRoleInfo::getRoleCode).collect(Collectors.toSet());
    }

    /**
     * 获取当前用户所有权限编码集合
     */
    public static Set<String> getCurrentUserPermissionCodeAll() {
        List<AuthRoleInfo.BaseRoleInfo> roles = getOnlineUserInfo().getRoles();
        // 返回用户所有权限编码
        if (roles == null) {
            return Collections.emptySet();
        }
        return roles.stream().map(AuthRoleInfo.BaseRoleInfo::getResourcePermission).flatMap(Collection::stream)
                .map(ResourcePermission::getPermissionCode).collect(Collectors.toSet());
    }

    /**
     * 设置拦截IP段
     */
    public static void setIpIntercept(SecurityProperties.IpIntercept ipIntercept) {
        if (ipIntercept != null) {
            Set<String> allow = securityProperties.getIpIntercept().getAllow();
            if (ipIntercept.getAllow() != null) {
                allow.addAll(ipIntercept.getAllow());
            }

            Set<String> deny = securityProperties.getIpIntercept().getDeny();
            if (ipIntercept.getDeny() != null) {
                deny.addAll(ipIntercept.getDeny());
            }
            RedisUtils.set(securityProperties.getCodeKey(AuthConstant.CACHE_IP_INTERCEPT_ALLOW), allow);
            RedisUtils.set(securityProperties.getCodeKey(AuthConstant.CACHE_IP_INTERCEPT_DENY), deny);
        }
    }
}
