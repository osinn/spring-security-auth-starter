package io.github.osinn.security.service;

import io.github.osinn.security.security.dto.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.List;

/**
 * 对外提供获取用户全部权限数据的接口
 *
 * @author wency_cai
 */
public interface ISecurityService {

    /**
     * 自定义登录认证,由内部接口 IOnlineUserService 调用
     *
     * @param principal
     * @return
     */
    default AuthUserInfo customAuth(Object principal) {
        return null;
    }

    /**
     * 查询用户全部权限
     *
     * @param userId 用户id
     * @return
     */
    AuthRoleInfo getRolePermissionInfo(Object userId);

    /**
     * 登录接口根据账号查询用户信息
     * <pre>
     *     Security auth  用户基本字段
     *      id              用户id    接口返回的对象id属性值最终被转成字符串类型
     *      account         登录账号
     *      nickname        用户名称
     *      password        登录账号密码(密码不会被缓存)
     *      extendField     扩展登录在线用户信息
     *      enabled         账户禁用/启用状态，boolean 类型
     * </pre>
     * 用户账号锁定、禁用等状态自行判断，如果账号锁定手动抛出SecurityAuthException异常即可
     *
     * @param account 登录账号
     * @return 返回用户Bean对象
     */
    AuthUserInfo loadUserByUsername(String account);

    /**
     * 自定义token,如果返回空，则调用默认的token生成规则
     *
     * @param authUserInfo token生成规则自定义
     * @return
     */
    default String getCustomizeToken(AuthUserInfo authUserInfo) {
        return null;
    }

    /**
     * 每次校验权限都会调用此方法获取系统全部权限，如果需要缓存自行处理，默认会缓存，如果配置 enableSysResourcePermissionAll = false,需要自行处理缓存，避免频繁查询数据库获取系统所有权限权限
     *
     * @return 返回系统全部权限
     */
    List<ResourcePermission> getSysResourcePermissionAll();

    /**
     * 白名单路径不会被调用
     * 检查登陆完成后，在调用登录认证 doFilter 过滤器前执行一次此方法
     * 可以使用此方法做额外处理
     *
     * @param request
     * @param response
     */
    default void doFilterBeforeHandler(HttpServletRequest request, HttpServletResponse response) {

    }

    /**
     * 检查登陆完成并且执行登录认证 doFilter 过滤器后执行一次此方法
     * 可以使用此方法做额外处理
     *
     * @param request
     * @param response
     */
    default void doFilterAfterHandler(HttpServletRequest request, HttpServletResponse response) {

    }

    /**
     * 登录通知，非customAuth 登录方式
     *
     * @param loginStatus    登录状态，true 登录成功，false 登录失败
     * @param authLoginParam 登录时提交的登录信息
     * @param request
     * @param response
     */
    default void loginNotification(boolean loginStatus, AuthLoginParam authLoginParam, String exceptionMsg, HttpServletRequest request, HttpServletResponse response) {

    }

    /**
     * 内部完成刷新token后触发
     */
    default void doRenewToken(OnlineUser onlineUser, HttpServletRequest request, HttpServletResponse response) {

    }
}
