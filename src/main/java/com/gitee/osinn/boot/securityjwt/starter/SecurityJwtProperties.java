package com.gitee.osinn.boot.securityjwt.starter;

import com.google.common.collect.Sets;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;
import com.gitee.osinn.boot.securityjwt.enums.AuthType;
import com.gitee.osinn.boot.securityjwt.utils.DesEncryptUtils;

import java.util.Set;

/**
 * Jwt参数配置-token使用redis过期策略
 *
 * @author wency_cai
 */
@Data
@ConfigurationProperties(prefix = SecurityJwtProperties.PREFIX)
public class SecurityJwtProperties {

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
    private Long tokenValidityInSeconds = 14400L;

    /**
     * 可选-额外自定义白名单路径
     */
    private Set<String> ignoringUrls = Sets.newLinkedHashSet();

    /**
     * 可选-额外自定义黑名单路径
     */
    private Set<String> authUrlsPrefix = Sets.newLinkedHashSet();

    /**
     * 必须-密码加密的私钥
     */
    private String rsaPrivateKey;

    /**
     * 可选-应用启动删除旧的之前的toekn
     */
    private boolean appRunDeleteHistoryToken;

    /**
     * 可选-踢掉之前已经登录的token
     */
    private boolean singleLogin;

    /**
     * 可选-8位字节的DES加密密码-保存在线用户信息是toekn将通过des加密后保存
     */
    private String desPassword;

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
     * 权限不足或认证失败是否抛出异常，true 抛出SecurityJwtException异常
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
     *   "code": 20000,
     *   "message": "退出登录成功",
     *   "error": null,
     *   "path": "/logout",
     *   "timestamp": "2021-06-29 12:16:28"
     * }
     */
    private boolean loginOutResponse = true;

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
    private AuthType authType = AuthType.URL;

    /**
     * 是否动态刷新token
     */
    private boolean dynamicRefreshToken;

    /**
     * 验证码
     */
    private CaptchaCode captchaCode = new CaptchaCode();

    public void setDesPassword(String desPassword) {
        this.desPassword = desPassword;
        DesEncryptUtils.setDesPassword(desPassword);
    }

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
