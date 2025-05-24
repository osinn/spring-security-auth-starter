# spring-security-auth-starter
- 目标 spring-security 权限认证自动配置，开箱即用，减少开发成本
- 支持动态续租token过期时间
- 支持基于`@PreAuthorize`注解方式授权认证
- 支持基于URL路径权限认证。登录接口前端可对密码进行rsa加密(前端公钥加密，后端私钥解密)
- 支持自定义登录接口(微信公众授权/小程序授权可选自定义登录接口)
- `@AuthIgnore` 注解，用于标识接口是否需要认证

# Spring Boot 版本
- 基于`Spring boor v3.5.0`版本重构
- 需要jdk17+

# 地址
- 项目地址 ：[https://github.com/wency-cai/spring-security-auth-starter](https://github.com/wency-cai/spring-security-auth-starter)
- demo 地址：[https://github.com/osinn/spring-security-auth-example](https://github.com/osinn/spring-security-auth-example)


# 快速开始
#### 引入依赖

```
<dependency>
    <groupId>io.github.osinn</groupId>
    <artifactId>spring-security-auth-starter</artifactId>
    <version>最新版本</version>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

#### yml 简易配置
```
security:
  config:
    # 建议换成自己的密码
    des-password: 123456789
    expire-time: 14400 # 过期时间默认4小时
    expire-ratio: 0.5 # 过期时间剩余比例，0-1之间，默认 0.5 即时间过半时刷新token缓存过期时间
    dynamic-refresh-token: true # 开启启动刷新token，默认是关闭的，不会自动刷新token过期时间，开启后，token会根据 expire-ratio 比例阀值计算是否需求重置token过期时间
    # 匿名访问url
    ignoring-urls:
      - /login # 登录接口忽略认证
```
- 这里的配置只是一部分的配置，更多配置请查看项目代码

# 启动类
- 在启动类添加如下注解启用`spring-security-auth-starter`安全认证

```
@EnableSecurityAuth
```

#### 实现 ISecurityService 接口
- `ISecurityService`接口是用来实现登录，获取用户权限等信息

```

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import io.github.osinn.example.entity.UserEntity;
import io.github.osinn.example.service.IUserService;
import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.dto.*;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.CryptoUtils;
import io.github.osinn.security.utils.StrUtils;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * 示例
 *
 * @author wency_cai
 */
@Slf4j
@Service
public class SecurityServiceImpl implements ISecurityService {

    @Resource
    private IUserService userService;

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private PasswordEncoder passwordEncoder;

//    /**
//     * 自定义登录
//     * 如果是微信授权登录可以使用自定义登录接口 返回AuthUserInfo 信息即可
//     *
//     * @param principal 登录接口登录信息对象，由开发者自己定义传入
//     * @return
//     */
//    @Override
//    public AuthUserInfo customAuth(Object principal) {
//        AuthLoginParam authLoginParam = (AuthLoginParam) principal;
//
//        UserEntity userEntity = userService.getOne(Wrappers.lambdaQuery(UserEntity.class)
//                .eq(UserEntity::getAccount, authLoginParam.getAccount())
//        );
//
//        String password;
//        if (!StrUtils.isEmpty(securityProperties.getRsaPrivateKey())) {
//            try {
//                password = CryptoUtils.rsaDecrypt(authLoginParam.getPassword(), securityProperties.getRsaPrivateKey());
//            } catch (Exception e) {
//                log.error(e.getMessage(), e);
//                throw new SecurityAuthException(AuthHttpStatus.PASSWORD_ERROR.getCode(), AuthHttpStatus.TOKEN_UNAUTHORIZED.getMessage());
//            }
//        } else {
//            password = authLoginParam.getPassword();
//        }
//
//        if (!passwordEncoder.matches(password, userEntity.getPassword())) {
//            throw new BadCredentialsException(AuthHttpStatus.TOKEN_UNAUTHORIZED.getMessage());
//        }
//
//        AuthUserInfo authUserInfo = new AuthUserInfo();
//        authUserInfo.setId(userEntity.getId());
//        authUserInfo.setNickname(userEntity.getUserName());
//        authUserInfo.setAccount(userEntity.getAccount());
//
//        return authUserInfo;
//    }

    /**
     * 根据账号获取用户信息
     *
     * @param account
     * @return AuthUserInfo
     */
    @Override
    public AuthUserInfo loadUserByUsername(String account) {
        UserEntity userEntity = userService.getOne(Wrappers.lambdaQuery(UserEntity.class)
                .eq(UserEntity::getAccount, account)
        );
        if (userEntity == null) {
            return null;
        }

        return new AuthUserInfo(
                userEntity.getId(),
                userEntity.getAccount(),
                userEntity.getUserName(),
                userEntity.getPassword(),
                null, // 如果需要额外扩展用户信息，请自赋值一个对象即可, 从在线用户信息中获取 -> onlineUser.getExtendField() 即为此处传入的对象
                null, // 不需要赋值，内置会自行处理
                null, // 不需要赋值，内置会自行处理
                null, // 不需要赋值，内置会自行处理
                null // 不需要赋值，内置会自行处理
        );
    }

    /**
     * 获取用户的角色以及权限
     *
     * @param userId
     * @return
     */
    @Override
    public AuthRoleInfo fetchRolePermissionInfo(Serializable userId) {
        AuthRoleInfo jwtRoleInfo = new AuthRoleInfo();

        List<ResourcePermission> resourcePermissionList = new ArrayList<>();
        resourcePermissionList.add(new ResourcePermission(null, "sys:user:list", "用户管理"));

        AuthRoleInfo.BaseRoleInfo roleInfo = new AuthRoleInfo.BaseRoleInfo(1, "demo", "test", null, resourcePermissionList);

        jwtRoleInfo.setRoles(List.of(roleInfo));
        return jwtRoleInfo;
    }

    /**
     * 获取系统所有资源权限
     *
     * @return
     */
    @Override
    public List<ResourcePermission> getSysResourcePermissionAll() {
        List<ResourcePermission> resourcePermissionList = new ArrayList<>();
        resourcePermissionList.add(new ResourcePermission(null, "sys:user:list", "用户管理"));
        resourcePermissionList.add(new ResourcePermission(null, "sys:user:list2", "用户管理2"));
        return resourcePermissionList;
    }

}
```
