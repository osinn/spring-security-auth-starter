package io.github.osinn.security.utils;

import cn.hutool.core.util.IdUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityJwtProperties;
import io.github.osinn.security.constants.JwtConstant;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.JwtRoleInfo;
import com.google.common.base.Charsets;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.ContentCachingRequestWrapper;

import jakarta.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

/**
 * token工具类
 *
 * @author wency_cai
 **/
@Slf4j
@Component
public class TokenUtils {

    private static SecurityJwtProperties securityJwtProperties;
    private static IOnlineUserService onlineUserService;


    public TokenUtils(SecurityJwtProperties securityJwtProperties, IOnlineUserService onlineUserService) {
        TokenUtils.securityJwtProperties = securityJwtProperties;
        TokenUtils.onlineUserService = onlineUserService;
    }

    /**
     * 创建token
     *
     * @return
     */
    public static String createToken() {
        return IdUtil.simpleUUID().toUpperCase();
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
        String bearerToken = request.getHeader(securityJwtProperties.getHeader());
        if (!StrUtils.isEmpty(bearerToken) && bearerToken.startsWith(securityJwtProperties.getTokenStartWith())) {
            return bearerToken.replace(securityJwtProperties.getTokenStartWith(), "");
        }
        return null;
    }

    /**
     * 支持从请求头、get请求、post表单JSON数据中获取token
     *
     * @param httpServletRequest
     * @return
     */
    public static String getServiceName(HttpServletRequest httpServletRequest) {
        String serviceName = httpServletRequest.getHeader(securityJwtProperties.getServiceName());
        String serviceHandlerMethod = httpServletRequest.getHeader(securityJwtProperties.getServiceHandlerMethod());
        if (StrUtils.isEmpty(serviceName)) {
            serviceName = httpServletRequest.getParameter(securityJwtProperties.getServiceName());
            serviceHandlerMethod = httpServletRequest.getParameter(securityJwtProperties.getServiceHandlerMethod());
            if (StrUtils.isEmpty(serviceName) && AuthType.SERVICE.equals(securityJwtProperties.getAuthType())) {
                try (BufferedReader streamReader = new BufferedReader(new InputStreamReader(httpServletRequest.getInputStream(), Charsets.UTF_8))) {
                    StringBuffer body = new StringBuffer();
                    String inputStr = null;
                    while ((inputStr = streamReader.readLine()) != null) {
                        body.append(inputStr);
                    }
                    String bodyStr = body.toString();
                    if (!StrUtils.isEmpty(bodyStr)) {
                        JSONObject jsonObject = JSONUtil.parseObj(bodyStr);
                        if (!jsonObject.isEmpty()) {
                            serviceName = String.valueOf(jsonObject.get(securityJwtProperties.getServiceName()));
                            if (!StrUtils.isEmpty(jsonObject.get(securityJwtProperties.getServiceHandlerMethod()))) {
                                serviceHandlerMethod = (String) jsonObject.get(securityJwtProperties.getServiceHandlerMethod());
                            }
                        }
                    }
                } catch (IOException e) {
                    log.debug("获取服务名称-HttpServletRequest 尝试解析表单请求json数据失败：" + e.getMessage(), e);
                }
            }
        }

        if (!StrUtils.isEmpty(serviceHandlerMethod) && !StrUtils.isEmpty(serviceName)) {
            serviceName = serviceName + JwtConstant.POINT + serviceHandlerMethod;
        }
        return serviceName;
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
        List<JwtRoleInfo.BaseRoleInfo> roles = fetchOnlineUserInfo().getRoles();
        return roles != null && roles.stream().anyMatch(item -> item.getRoleCode().equals(JwtConstant.SUPER_ADMIN_ROLE));
    }

    /**
     * 判断是否包含admin角色
     * 角色 entity可以继承JwtRoleInfo.BaseRoleInfo类方便传值
     *
     * @return 如果是超级管理员返回true否则false
     */
    public static Boolean hasRoleAdmin(List<JwtRoleInfo.BaseRoleInfo> roles) {
        if (roles == null || roles.isEmpty()) {
            return false;
        }
        return roles.stream().anyMatch(item -> item.getRoleCode().equals(JwtConstant.SUPER_ADMIN_ROLE));
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
