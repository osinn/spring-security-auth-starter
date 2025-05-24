package io.github.osinn.security.starter;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.enums.AuthType;
import com.google.common.collect.Sets;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 参数配置-token使用redis过期策略
 *
 * @author wency_cai
 */
@Data
@ConfigurationProperties(prefix = SecurityProperties.PREFIX)
public class SecurityProperties {

    public final static String PREFIX = "security.config";

    /**
     * 可选- Request Headers ： Authorization
     */
    private String header = "Authorization";

    /**
     * 可选-令牌前缀，最后留个空格 Bearer
     */
    private String tokenStartWith = "Bearer ";

    /**
     * 可选-令牌过期时间 此处单位/秒。默认 4 时
     */
    private Long expireTime = 14400L;

    /**
     * 可选-额外自定义白名单路径
     */
    private Set<String> ignoringUrls = Sets.newLinkedHashSet();

    /**
     * 可选-额外自定义黑名单路径
     */
    private Set<String> authUrlsPrefix = Sets.newLinkedHashSet();

    /**
     * 白名单token，完成的token,包括 tokenStartWith
     */
    private Set<String> ignoringToken = Sets.newLinkedHashSet();

    /**
     * 可选-密码加密的私钥
     */
    private String rsaPrivateKey;

    /**
     * 可选-应用启动删除旧的之前的token
     */
    private boolean appRunDeleteHistoryToken;

    /**
     * 可选-踢掉之前已经登录的token
     */
    private boolean singleLogin;

    /**
     * 可选-8位字节的DES加密密码-保存在线用户信息是toekn将通过des加密后保存
     */
    private String desPassword = "aMQBIx+Yta0=";

    /**
     * 可选-禁用Http Basic
     */
    private boolean disableHttpBasic = true;
    /**
     * 可选-禁用CSRF
     */
    private boolean disableCsrf = true;

    /**
     * 是否启用跨域请求配置
     */
    private boolean enableCors = true;

    /**
     * 是否开启xss()
     */
    private boolean enableXss = true;

    /**
     * 权限不足或认证失败是否抛出异常，true 抛出SecurityAuthException异常
     * false  http请求状态为200,输出以下格式内容
     * {
     * "path": "/api/index",
     * "message": "token已过期",
     * "error": "token已过期",
     * "status": "4007",
     * "timestamp": "2021-06-29 12:16:28"
     * }
     */
    private boolean authFailThrows;

    /**
     * 当退出成功是否自动响应内容，内容格式如下
     * {
     * "code": 20000,
     * "message": "退出登录成功",
     * "error": null,
     * "path": "/logout",
     * "timestamp": "2021-06-29 12:16:28"
     * }
     */
    private boolean loginOutResponse = true;

    /**
     * 自定义权限不足、认证失败、退出成功响应字段名
     * 例如
     * - message: msg # 默认message
     * - error: error_msg # error
     * - code: code # 默认code
     * <p>
     * jsonObject.set("message", message);
     * jsonObject.set("error", errorMessage);
     * jsonObject.set("code", statusCode);
     */
    private Map<String, String> responseBody = new HashMap<>();

    /**
     * 可选-加密方式：
     * <p> bcrypt </p>
     * <p> pbkdf2 </p>
     * <p> md5sha512 先sha512在md5然后字母转大写 </p>
     */
    private String idForEncode = "md5sha512";

    /**
     * 默认根据url认证
     */
    private AuthType authType = AuthType.CODE;

    /**
     * 登陆来源，可根据需要使用
     */
    private String loginSource;

    /**
     * 是否动态刷新token,若果要动态刷新token,需要在缓存对象OnlineUser中设置登录时间
     */
    private boolean dynamicRefreshToken;

    /**
     * 验证码
     */
    private CaptchaCode captchaCode = new CaptchaCode();

    /**
     * 多环境值，用途：多环境下，请求头携带的值与设定的值一直请求放行，否则拦截请求，空则忽略
     * 应用场景：小程序多环境配置项目，上生产时，前端不小心使用测试环境打包发布上线，请求接口携带envTag值，服务端效验envTag拦截请求及时告知请求环境地址错误
     */
    private String envTag;

    /**
     * 多环境环境请求头参数名称
     */
    private String headerEnvTagName;

    /**
     * 缓存在线用户信息key前缀
     */
    private String cacheOnlineUserInfoKeyPrefix = AuthConstant.CACHE_ONLINE_USER_INFO_KEY_PREFIX;

    /**
     * 是否开启系统资源权限查询缓存，开启后，在查询系统全部权限时会缓存起来，如果系统权限有变动，需要请手动调用清理缓存方法
     */
    private boolean enableSysResourcePermissionAll = true;

    /**
     * 验证码
     */
    @Data
    public static class CaptchaCode {

        /**
         * 可选
         * 若果不实用内置的，可以自行实现验证码校验
         * 是否启用内置验证码验证，如果开启，总会进行校验图形验证码
         */
        private boolean enable = false;

        /**
         * 使用方式：
         * 配置验证缓存前缀key即为 codeKey
         * 生成验证码并生成唯一值例如 uuid 并且 codeKey+uuid 作为redis key缓存验证码
         * uuid发送给客户端，客户端提交请求携带验证码以及uuid
         */
        private String codeKey = "admin_captcha_code:";

        /**
         * redis中验证码有效期3分钟（单位：秒）
         */
        private long captchaExpiration = 60 * 3;
    }
}
