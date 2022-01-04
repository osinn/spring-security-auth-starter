package com.gitee.osinn.boot.securityjwt.constants;

/**
 * @author wency_cai
 * @description: 描述
 **/
public class JwtConstant {


    public final static String UNKNOWN = "unknown";
    public final static String PROXY_CLIENT_IP = "Proxy-Client-IP";
    public final static String X_FORWARDED_FOR = "x-forwarded-for";
    public final static String WL_PROXY_CLIENT_IP = "WL-Proxy-Client-IP";
    public final static String UA = "User-Agent";

    public final static String LOCALHOST = "127.0.0.1";
    /**
     * 用于IP定位转换
     */
    public final static String REGION = "内网IP|内网IP";

    public final static String ONLINE_USER_INFO_KEY_PREFIX = "online_user_info:key_";
    /**
     * 下面两个key只是为了定义删除全部数据用
     */
    public final static String ONLINE_TOKEN_KEY = "security_jwt_online_token";
    public final static String ONLINE_USER_INFO_KEY = "online_user_info";

    /**
     * fetchResourcePermissionAll接口数据缓存key
     * 在 JwtAppRun中调用删除
     */
    public final static String RESOURCE_PERMISSION = "resource_permission";

    /**
     * 超级管理管理，角色编码
     */
    public final static String SUPER_ADMIN_ROLE = "admin";

    public final static String POINT = ".";
}
