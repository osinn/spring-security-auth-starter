# spring-security-auth-starter
> spring-security 权限认证自动配置，开箱即用

# 快速开始
- 在`Spring Boot`项目中引入以下依赖
```
<dependency>
    <groupId>com.gitee.osinn</groupId>
    <artifactId>spring-security-auth-starter</artifactId>
    <version>1.0</version>
</dependency>
```
# `application.yml`配置
```
security:
  config:
    # 是否启用跨域请求配置
    enableCors: false
    # token 请求头名称
    header: Authorization
    # 令牌前缀
    token-start-with: TestBearer
    # 令牌过期时间 此处单位/毫秒 ，默认4小时，可在此网站生成 https://www.convertworld.com/zh-hans/time/milliseconds.html
  #  token-validity-in-seconds: 60000
    token-validity-in-seconds: 14400000
    #  验证码 key(配置key意味着对验证码进行校验)
    #  使用方式：
    #        配置验证缓存前缀key即为 codeKey
    #        生成验证码并生成唯一值例如 uuid 并且 codeKey+uuid 作为redis key缓存验证码
    #        uuid发送给客户端，客户端提交请求携带验证码以及uuid
    #  code-key: code-key
    # 是否踢掉之前已经登录的token
    single-login: false
    # 匿名访问url
    ignoring-urls:
      - /api/ignoringUrls
      - /redissonTest/**
    # token校验访问url
    auth-urls-prefix:
      - /auto/demo
    # 密码加密的私钥, 密码加密传输，前端公钥加密，后端私钥解密
#    rsa-private-key: MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEA0vfvyTdGJkdbHkB8mp0f3FE0GYP3AYPaJF7jUd1M0XxFSE2ceK3k2kw20YvQ09NJKk+OMjWQl9WitG9pB6tSCQIDAQABAkA2SimBrWC2/wvauBuYqjCFwLvYiRYqZKThUS3MZlebXJiLB+Ue/gUifAAKIg1avttUZsHBHrop4qfJCwAI0+YRAiEA+W3NK/RaXtnRqmoUUkb59zsZUBLpvZgQPfj1MhyHDz0CIQDYhsAhPJ3mgS64NbUZmGWuuNKp5coY2GIj/zYDMJp6vQIgUueLFXv/eZ1ekgz2Oi67MNCk5jeTF2BurZqNLR3MSmUCIFT3Q6uHMtsB9Eha4u7hS31tj1UWE+D+ADzp59MGnoftAiBeHT7gDMuqeJHPL4b+kC+gzV4FGTfhR9q3tTbklZkD2A==
    # 指定des加密密码。登录成功后，token也会跟随用户信息缓存起来，经过des加密，
    des-password: 12345678
    # 启动系统后是否删除登录过的token
    app-run-delete-history-token: false
    # 配置用户密码加密方式
    id-for-encode: bcrypt
    # 权限认证方式，CODE或URL,不管使用哪种方式调调用fetchRolePermissionInfo方法查询权限
    # com.gitee.osinn.boot.securityjwt.service.ISecurityService.fetchRolePermissionInfo()
    # 如果是URL方式调用fetchResourcePermissionAll()方法查询资源路径(UIR)以及资源路径权限编码
    auth-type: CODE
```

# 使用方式
- 在启动类上添加`@EnableSecurityJwt`注解启用自动配置
- 在启动类上添加`@DisableSecurityJwt`注解禁用`Spring security`自动配置

# 如果在项目中引入此依赖，不想用内置的加密方法式，可以自行注入自定义加密，注入方式如下
```
@Bean
public PasswordEncoder passwordEncoder() {
    // CustomizePasswordEncoder则是自定义密码加密方式类
    // CustomizePasswordEncoder.class可以参考 com.gitee.osinn.boot.securityjwt.security.crypto.Md5Sha512PasswordEncoder
    return new CustomizePasswordEncoder();
}
```

# 新增用户密码加密
```
// 新增一个账号
userEntity = new SysUserEntity();
userEntity.setAccount("demo");
userEntity.setNickname("演示");
userEntity.setStatus(StatusEnum.ENABLE);
// idForEncode为配置用户密码加密方式
PasswordEncoder passwordEncoder = PasswordEncoderUtils.getPasswordEncoder(idForEncode);
userEntity.setPassword(passwordEncoder.encode("12345600")); // 密码加密
sysUserMapper.insert(userEntity);
```

# 图形验证码
- 使用内置实现图形验证码，引入依赖

```
<!-- 图形验证码依赖包 -->
<dependency>
    <groupId>com.github.whvcse</groupId>
    <artifactId>easy-captcha</artifactId>
    <version>${easy-captcha.version}</version>
</dependency>
```
# 自定义图形验证码
> 实现 ISecurityCaptchaCodeService 接口里面的方法即可

# 权限认证方式
- 基于url路径授权
- 在配置文件中如果不将`security.config.auth-type`指定为`URL`,那么使用security默认的 `@PreAuthorize`注解方式路径授权，例如：`@PreAuthorize("hasAuthority('system:sysMenu:details')")`，默认为`URL`

# `IOnlineUserService`接口
- 在需要的地方直接注入

```
@Autowired
private IOnlineUserService onlineUserService;
```
- 接口具有的方法

```
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
```
