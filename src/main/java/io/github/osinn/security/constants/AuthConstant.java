package io.github.osinn.security.constants;

/**
 * @author wency_cai
 **/
public class AuthConstant {


    public static final String UNKNOWN = "unknown";
    public static final String PROXY_CLIENT_IP = "Proxy-Client-IP";
    public static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String WL_PROXY_CLIENT_IP = "WL-Proxy-Client-IP";
    public static final String UA = "User-Agent";

    public static final String LOCALHOST = "127.0.0.1";

    public static final String CACHE_ONLINE_USER_INFO_KEY_PREFIX = "online_user_info:key_";

    /**
     * 超级管理管理，角色编码
     */
    public static final String SUPER_ADMIN_ROLE = "admin";

    /**
     * 在线用户ID key
     */
    public static final String ONLINE_USER_ID = "online_user_id";

    /**
     * 角色/权限分隔符
     */
    public static final String DELIMETER = "\\|";

    /**
     * 所有权限标识
     */
    public static final String ALL_PERMISSION = "*:*:*";

    /**
     * 缓存系统所有资源权限 key
     */
    public static final String SYS_RESOURCE_PERMISSION_ALL_CACHE_KEY = "io.github.osinn.security.sys_resource_permission_all";
}
