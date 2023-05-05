# spring-security-auth-starter
- spring-security 权限认证自动配置，开箱即用
- 支持动态续租token过期时间
- 支持统一API服务接口调用权限认证
- 支持基于`@PreAuthorize`注解方式授权认证
- 支持基于URL路径权限认证。登录接口前端可对密码进行rsa加密(前端公钥加密，后端私钥解密)
- 支持自定义登录接口(微信公众授权/小程序授权可选自定义登录接口)
- 支持与Spring cloud集成
- 
# Spring Security版
- master分支基于 Spring boot 3.x版本，Spring security 6.X版本
- security-v5.7.X分支 分支基于 Spring boot 2.x版本，Spring security 5.7.X版本

# 项目地址
- github：[https://github.com/wency-cai/spring-security-auth-starter](https://github.com/wency-cai/spring-security-auth-starter)

# demo
- 地址：[https://github.com/osinn/spring-security-auth-example](https://github.com/osinn/spring-security-auth-example)
# Spring boot 项目依赖
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<!-- redis -->
<dependency>
    <groupId>org.redisson</groupId>
    <artifactId>redisson-spring-boot-starter</artifactId>
    <version>${version}</version>
</dependency>
```
# 快速开始
- 在`Spring Boot`项目中引入以下依赖
```
<dependency>
  <groupId>io.github.osinn</groupId>
  <artifactId>spring-security-auth-starter</artifactId>
  <version>2.0-beta0</version>
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
    auth-type: CODE  # 值为OFF 关闭权限认证¸只认证登录，不认证权限
     #  前端传服务名称之属性名称
    service-name: service
    # 前端传服务接口方法名称之属性名称 可选（有一种架构请求服务只根据服务名称调用业务接口，此时service-handler-method可不指定）
    service-handler-method: methodName # 参与权限认证
#    如果是api服务层,前端需要传参数：接口方法名称
#    如果设置为true，需要service-handler-method 指定前端要调用的方法的参数名称
#    这时前端不只是传serviceName 需要调用的服务，还要传 serviceHandlerMethod具体要调用服务下的哪个接口方法
    api-service: true
    # 是否需要动态续租token过期时间
    dynamic-refresh-token: true
    # 默认启用xss配置，web标签转义字符
    enable-xss: true
    # 自定义权限不足、认证失败、退出成功响应字段名
    response-body:
      - message: msg # 默认message
      - error: error_msg # error
      - code: code # 默认code
    # 多环境值，用途：多环境下，请求头携带的值与设定的值一直请求放行，否则拦截请求，空则忽略
    # 应用场景：小程序多环境配置项目，上生产时，前端不小心使用测试环境打包发布上线，请求接口携带envTag值，服务端效验envTag拦截请求及时告知请求环境地址错误
    env-tag: test # 测试环境
    # 多环境环境请求头参数名称
    header-env-tag-name: environment  
    ...
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
- 在配置文件中如果不将`security.config.auth-type`指定为`URL`,那么使用security默认的 `@PreAuthorize`注解方式路径授权，例如：`@PreAuthorize("hasAuthority('system:sysMenu:details')")`
- 默认为`URL`，即为基于url路径授权
- `SERVICE`方式结合@API注解使用，用于通过服务名称来请求业务接口

# xss
> 默认`enable-xss: true`启用xss配置，web标签转义字符

- 如果想要json也要xss配置转义web标签，需要配置如下

```
@Bean
public HttpMessageConverters fastJsonHttpMessageConverters() {
    MappingJackson2HttpMessageConverter jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
    ObjectMapper objectMapper = new ObjectMapper();
    SimpleModule simpleModule = new SimpleModule();
    // 添加MyHttpServletRequestJacksonDeserializer解析器
    simpleModule.addDeserializer(String.class, new MyHttpServletRequestJacksonDeserializer());
    objectMapper.registerModule(simpleModule);
    jackson2HttpMessageConverter.setObjectMapper(objectMapper);
    return new HttpMessageConverters(jackson2HttpMessageConverter);
}
```

# 关于@API注解、@APIMethodPermission注解
> demo: [https://github.com/wency-cai/spring-security-auth-example.git](https://github.com/wency-cai/spring-security-auth-example.git)

## @API注解
```
/**
 * 服务API注解，在类上添加此注解
 * <p>
 * 有时候我们调用的接口是通过注解指定服务名称
 * 前端通过指定服务名称调用接口
 * </p>
 *
 * @author wency_cai
 **/
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Component
public @interface API {

    /**
     * 服务名称-应用场景：用于通过服务名称调用接口指定的服务名称
     *
     * @return 服务名称
     */
    String service();

    /**
     * 是否需要认证登录
     *
     * @return true 需要认证登录，false 不需要认证登录
     */
    boolean needLogin() default false;

    /**
     * 接口拥有的权限
     *
     * @return 权限code
     */
    String permission() default "";

    /**
     * 是否需要权限认证
     *
     * @return true 需要认证权限，false 不需要认证权限
     */
    boolean needPermission() default false;
}
```
## @APIMethodPermission注解
```
/**
 * 服务API注解，在方法上添加此注解校验方法权限
 *
 * @author wency_cai
 **/
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface APIMethodPermission {

    /**
     * 是否需要认证登录
     *
     * @return true 需要认证登录，false 不需要认证登录
     */
    boolean needLogin() default false;

    /**
     * 接口拥有的权限
     *
     * @return 权限code
     */
    String permission() default "";

    /**
     * 是否需要权限认证
     *
     * @return true 需要认证权限，false 不需要认证权限
     */
    boolean needPermission() default false;
}
```

## 示例
```
@API(service = SERVICE_NAME)
@Service(SERVICE_NAME)
public class UserServiceImpl implements IUserService {

    public static final String SERVICE_NAME = "userService";
    
    @Override
    @APIMethodPermission(needLogin = true, permission = "test:111", needPermission = true)
    public List<UserVO> getUserAll() {
        List<UserVO> userVOList = new ArrayList<>();
        UserVO userVO = new UserVO();
        userVO.setId(1);
        userVO.setName("测试");
        userVOList.add(userVO);
        return userVOList;
    }
}
```

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
# 手动获取权限编码
- 获取当前用户拥有的权限

```
Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
for (GrantedAuthority authority : authorities) {
    System.out.println(authority.getAuthority());
}

// 或者调用fetchOnlineUserCompleteInfo()方法获取当前在线用户信息从而获取用户拥有的权限
IOnlineUserService.fetchOnlineUserCompleteInfo()
```

# 基于code权限认证 service 实现类
```java

import com.google.common.collect.Lists;
import io.github.osinn.security.security.dto.*;
import io.github.osinn.security.service.ISecurityService;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * 授权服务
 *
 * @author wency_cai
 */
@Service
public class SecurityServiceImpl implements ISecurityService {

    /**
     * 自定义登录接口
     *
     * @param principal(为登陆接口传的参数)
     * @return
     */
    @Override
    public JwtUser customAuth(Object principal) {
        // principal 自行转换得到对应对象
        JwtUser jwtUser = new JwtUser();
        jwtUser.setId(1401043674048851970L);
        jwtUser.setNickname("测试");
        jwtUser.setAccount("test");

        return jwtUser;
    }

    /**
     * 获取用户的角色以及权限
     *
     * @param userId
     * @return
     */
    @Override
    public JwtRoleInfo fetchRolePermissionInfo(Object userId) {
        JwtRoleInfo jwtRoleInfo = new JwtRoleInfo();
        JwtRoleInfo.BaseRoleInfo baseRoleInfo = new JwtRoleInfo.BaseRoleInfo();

        ResourcePermission resourcePermission = new ResourcePermission();
        resourcePermission.setUriPath("/test/demo");
        resourcePermission.setPermissionCode("test.demo");
        resourcePermission.setMenuName("测试");


        baseRoleInfo.setRoleCode("test");
        baseRoleInfo.setId(1);
        baseRoleInfo.setName("test");
        baseRoleInfo.setResourcePermission(Lists.newArrayList(resourcePermission));
        jwtRoleInfo.setRoles(Lists.newArrayList(baseRoleInfo));
//
//        JwtRoleInfo jwtRoleInfo = new JwtRoleInfo();
//        jwtRoleInfo.setRoles(Lists.newArrayList());
        return jwtRoleInfo;
    }


    @Override
    public Object loadUserByUsername(String account) {
        return null;
    }

    @Override
    public String getCustomizeToken(JwtUser jwtUser) {
        return null;
    }

    @Override
    public void logoutBeforeHandler(HttpServletRequest request, HttpServletResponse response, OnlineUser loginUser) {

    }

    @Override
    public List<ResourcePermission> getSysResourcePermissionAll() {
        // 如果是小程序等api应用，接口没有权限控制的，这里可以直接返回空集合
        ResourcePermission resourcePermission = new ResourcePermission();
        resourcePermission.setUriPath("/test/demo");
        resourcePermission.setPermissionCode("test.demo");
        resourcePermission.setMenuName("测试");

        ResourcePermission resourcePermission2 = new ResourcePermission();
        resourcePermission2.setUriPath("/test/demo2");
        resourcePermission2.setPermissionCode("test.demo2");
        resourcePermission2.setMenuName("测试");
        return Lists.newArrayList(resourcePermission, resourcePermission2);
    }
}
```