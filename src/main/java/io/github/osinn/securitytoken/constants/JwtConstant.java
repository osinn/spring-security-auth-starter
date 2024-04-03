package io.github.osinn.securitytoken.constants;

/**
 * @author wency_cai
 **/
public class JwtConstant {

    public static final String UNKNOWN = "unknown";
    public static final String PROXY_CLIENT_IP = "Proxy-Client-IP";
    public static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String WL_PROXY_CLIENT_IP = "WL-Proxy-Client-IP";
    public static final String UA = "User-Agent";

    public static final String LOCALHOST = "127.0.0.1";
    /**
     * 用于IP定位转换
     */
    public static final String REGION = "内网IP";

    public static final String ONLINE_USER_INFO_KEY_PREFIX = "online_user_info:key_";
    /**
     * 下面两个key只是为了定义删除全部数据用
     */
    public static final String ONLINE_TOKEN_KEY = "security_jwt_online_token";
    public static final String ONLINE_USER_INFO_KEY = "online_user_info";

    /**
     * fetchResourcePermissionAll接口数据缓存key
     * 在 JwtAppRun中调用删除
     */
    public static final String RESOURCE_PERMISSION = "resource_permission";

    /**
     * 超级管理管理，角色编码
     */
    public static final String SUPER_ADMIN_ROLE = "admin";

    public static final String POINT = ".";

    public static final String CONTENT_TYPE = "Content-Type";

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
}
