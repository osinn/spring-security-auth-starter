# spring-security-auth-starter
- 目标 spring-security 权限认证自动配置，开箱即用，减少开发成本
- 支持动态续租token过期时间
- 支持基于`@PreAuthorize`注解方式授权认证
- 支持基于URL路径权限认证。登录接口前端可对密码进行rsa加密(前端公钥加密，后端私钥解密)
- 支持自定义登录接口(微信公众授权/小程序授权可选自定义登录接口)

# Spring Boot 版本
- 基于`Spring boor v3.5.0`版本重构
- 需要jdk17+

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
#### 实现 ISecurityService 接口
- `ISecurityService`接口是用来实现登录，获取用户权限等信息


# 项目地址
- github：[https://github.com/wency-cai/spring-security-auth-starter](https://github.com/wency-cai/spring-security-auth-starter)

# demo
- 地址：[https://github.com/osinn/spring-security-auth-example](https://github.com/osinn/spring-security-auth-example)
