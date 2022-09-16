package io.github.osinn.securitytoken.service;

import io.github.osinn.securitytoken.security.dto.OnlineUser;
import io.github.osinn.securitytoken.exception.SecurityJwtException;
import io.github.osinn.securitytoken.security.dto.AuthUser;
import io.github.osinn.securitytoken.security.dto.JwtUser;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * 在线用户服务接口
 *
 * @author wency_cai
 */
public interface IOnlineUserService {

    /**
     * 自定义登录
     *
     * @param principal 登录请求信息
     * @param request
     * @return
     */
    JwtUser customAuth(Object principal, HttpServletRequest request);

    /**
     * 账号密码登录认证
     *
     * @param authUser
     * @param request
     * @return
     */
    JwtUser auth(AuthUser authUser, HttpServletRequest request, HttpServletResponse response) throws SecurityJwtException;

    /**
     * 退出登录删除token
     *
     * @throws SecurityJwtException 请求头不携带token抛出异常
     */
    void logout() throws SecurityJwtException;

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
    List<OnlineUser> fetchOnlineUserAllByUserId(Object filterUserId);

    /**
     * 获取当前在线用户
     *
     * @return
     */
    OnlineUser fetchOnlineUserCompleteInfo();

    /**
     * 根据token获取当前在线用户
     *
     * @return
     */
    OnlineUser fetchOnlineUserCompleteInfoByToken(String token);

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
     * 删除所有缓存
     */
    void deleteCacheAll();

    /**
     * 获取全部在线用户
     *
     * @return
     */
    List<OnlineUser> fetchOnlineUserAll();

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
    void editUserInfoForciblyLogout(List<Object> ids);

}
