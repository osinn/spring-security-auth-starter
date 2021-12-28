package com.gitee.osinn.boot.securityjwt.service;

import com.gitee.osinn.boot.securityjwt.security.dto.JwtRoleInfo;
import com.gitee.osinn.boot.securityjwt.security.dto.JwtUser;
import com.gitee.osinn.boot.securityjwt.security.dto.OnlineUser;
import com.gitee.osinn.boot.securityjwt.security.dto.ResourcePermission;
import com.gitee.osinn.boot.securityjwt.utils.TokenUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * 对外提供获取用户全部权限数据的接口
 *
 * @param <T> 用户Bean对象
 * @param <E> 主键数据类型
 * @author wency_cai
 */
public interface ISecurityService<T, E> {

    /**
     * 查询用户全部权限
     *
     * @param userId 用户id
     * @return
     */
    JwtRoleInfo fetchRolePermissionInfo(E userId);

    /**
     * security.config.auth-type=URL时使用，用于根据请求的URI判断权限code
     * security.config.auth-type=CODE时返回 null即可
     * 自行做缓存处理
     * 查询系统全部权限-带资源路径以及资源路径权限编码
     *
     * @return
     */
    List<ResourcePermission> fetchResourcePermissionAll();

    /**
     * 登录接口根据账号查询用户信息
     * <pre>
     *     Security jwt  用户基本字段
     *      id 用户id    接口返回的对象id属性值最终被转成字符串类型
     *      account     登录账号
     *      password    登录账号密码(如果需要缓存全部用户信息，密码不会被缓存)
     *      enabled     账户禁用/启用状态，boolean 类型
     * </pre>
     * 用户账号锁定、禁用等状态自行判断，如果账号锁定手动抛出SecurityJwtException异常即可
     *
     * @param account
     * @return 返回用户Bean对象
     */
    T loadUserByUsername(String account);

    /**
     * 自定义token,如果返回空，则调用默认的token生成规则
     *
     * @param jwtUser token生成规则自定义
     * @return
     */
    String getCustomizeToken(JwtUser jwtUser);

    /**
     * 退出(删除token)前处理方法
     *
     * @param loginUser
     */
    void logoutBeforeHandler(HttpServletRequest request, HttpServletResponse response, OnlineUser loginUser);

    /**
     * 获取服务名称 配合@API使用
     *
     * @param request
     * @return 返回服务名称
     */
    default String getServiceName(HttpServletRequest request) {
        String serviceName = TokenUtils.getServiceName(request);
        return serviceName;
    }
}
