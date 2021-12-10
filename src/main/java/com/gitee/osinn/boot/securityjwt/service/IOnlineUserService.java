package com.gitee.osinn.boot.securityjwt.service;

import com.gitee.osinn.boot.securityjwt.exception.SecurityJwtException;
import com.gitee.osinn.boot.securityjwt.security.dto.AuthUser;
import com.gitee.osinn.boot.securityjwt.security.dto.JwtUser;
import com.gitee.osinn.boot.securityjwt.security.dto.OnlineUser;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 在线用户服务接口
 *
 * @author wency_cai
 */
public interface IOnlineUserService {

    /**
     * 登录认证
     *
     * @param authUser
     * @param request
     * @return
     */
    JwtUser auth(AuthUser authUser, HttpServletRequest request);

    /**
     * 退出登录删除token
     *
     * @throws SecurityJwtException 请求头不携带token抛出异常
     */
    void logout() throws SecurityJwtException;

    /**
     * 根据用户id筛选在线的用户（多端登录，多个token对应一个用户）
     *
     * @param filterUserId
     * @return
     */
    List<OnlineUser> fetchOnlineUserAllByUserId(String filterUserId);

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
     */
    void refreshToken();

    /**
     * 根据用户ID删除token
     *
     * @param ids 用户id
     */
    void editUserInfoForciblyLogout(List<Object> ids);

}
