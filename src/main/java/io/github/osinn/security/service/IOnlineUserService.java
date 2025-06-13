package io.github.osinn.security.service;

import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.dto.AuthLoginParam;
import io.github.osinn.security.security.dto.AuthUserInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.List;

/**
 * 在线用户服务接口
 *
 * @author wency_cai
 */
public interface IOnlineUserService {

    /**
     * 生成token并缓存用户信息
     *
     * @param authUserInfo 用户信息
     * @param request
     */
    void generationToken(AuthUserInfo authUserInfo, HttpServletRequest request);

    /**
     * 自定义登录
     *
     * @param principal 登录请求信息
     * @param request
     * @return
     */
    AuthUserInfo customAuth(Object principal, HttpServletRequest request);

    /**
     * 账号密码登录认证
     *
     * @param authLoginParam
     * @param request
     * @return
     */
    AuthUserInfo auth(AuthLoginParam authLoginParam, HttpServletRequest request, HttpServletResponse response) throws SecurityAuthException;

    /**
     * 退出登录删除token
     *
     * @throws SecurityAuthException 请求头不携带token抛出异常
     */
    void logout() throws SecurityAuthException;

    /**
     * 存储token
     *
     * @param token      token值
     * @param onlineUser 登录用户的信息
     */
    void saveToken(String token, OnlineUser onlineUser);

    /**
     * 根据用户id筛选在线的用户（多端登录，多个token对应一个用户）
     *
     * @param filterUserId
     * @return
     */
    List<OnlineUser> getOnlineUserAllByUserId(Object filterUserId);

    /**
     * 获取当前在线用户
     *
     * @return
     * @throws SecurityAuthException 如果不存在会抛出异常
     */
    default OnlineUser getOnlineUserInfo() {
        return getOnlineUser(true);
    }


    /**
     * 获取当前在线用户
     *
     * @param throwEx 获取不到用户时是否抛出异常
     * @return
     */
    OnlineUser getOnlineUser(boolean throwEx);

    /**
     * 根据token获取当前在线用户
     *
     * @return
     */
    OnlineUser getOnlineUserInfoByToken(String token);

    /**
     * 根据指定的key查询在线用户
     *
     * @param key
     * @return
     */
    OnlineUser getOne(String key);

    /**
     * 根据前缀删除缓存
     *
     * @param prefixKey
     */
    void deleteCacheByPrefix(String prefixKey);

    /**
     * 获取全部在线用户
     *
     * @return
     */
    List<OnlineUser> getOnlineUserAll();

    /**
     * 刷新token缓存过期时间
     *
     * @param onlineUser 当前登陆用户
     */
    void refreshToken(OnlineUser onlineUser);

    /**
     * 根据用户ID删除token
     *
     * @param ids 用户id
     */
    void logoutForcibly(List<?> ids);

    /**
     * 刷新用户权限
     *
     * @param userId
     */
    void refreshUserPermission(Object userId);

    /**
     * 删除全部缓存，如系统权限权限缓存(不会清理token、登录用户信息)
     */
    void deleteCacheAll();

}
