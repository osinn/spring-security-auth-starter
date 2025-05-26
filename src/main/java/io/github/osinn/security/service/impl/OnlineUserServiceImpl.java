package io.github.osinn.security.service.impl;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.security.dto.*;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.service.ISecurityCaptchaCodeService;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.utils.*;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author wency_cai
 */
@Slf4j
@Component
public class OnlineUserServiceImpl implements IOnlineUserService {

    @Resource
    private ISecurityService securityService;

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Resource
    private RedisUtils redisUtils;

    @Resource
    private ISecurityCaptchaCodeService securityCaptchaCodeService;

    @Override
    public AuthUserInfo customAuth(Object principal, HttpServletRequest request) {
        AuthUserInfo authUserInfo = securityService.customAuth(principal);

        if (authUserInfo == null) {
            return null;
        }

        // 生成token
        this.generationToken(authUserInfo, request);

        return authUserInfo;
    }

    @Override
    public AuthUserInfo auth(AuthLoginParam authLoginParam, HttpServletRequest request, HttpServletResponse response) {

        SecurityProperties.CaptchaCode captchaCode = securityProperties.getCaptchaCode();
        if (captchaCode.isEnable()) {
            // 查询验证码
            String code = securityCaptchaCodeService.getCaptchaCode(authLoginParam.getUuid());
            // 清除验证码
            securityCaptchaCodeService.delete(authLoginParam.getUuid());
            if (StrUtils.isEmpty(code)) {
                throw new SecurityAuthException(AuthHttpStatus.NOT_FOUND_CODE.getCode(), AuthHttpStatus.NOT_FOUND_CODE.getMessage());
            }
            if (!code.equalsIgnoreCase(authLoginParam.getCode())) {
                throw new SecurityAuthException(AuthHttpStatus.CODE_UNAUTHORIZED.getCode(), AuthHttpStatus.CODE_UNAUTHORIZED.getMessage());
            }
        }

        String password;
        if (!StrUtils.isEmpty(securityProperties.getRsaPrivateKey())) {
            try {
                password = CryptoUtils.rsaDecrypt(authLoginParam.getPassword(), securityProperties.getRsaPrivateKey());

            } catch (Exception e) {
                log.error(e.getMessage(), e);
                throw new SecurityAuthException(AuthHttpStatus.PASSWORD_ERROR.getCode(), AuthHttpStatus.TOKEN_UNAUTHORIZED.getMessage());
            }
        } else {
            password = authLoginParam.getPassword();
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(authLoginParam.getAccount(), password);
        Authentication authentication = null;
        try {
            authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // 生成令牌
            AuthUserInfo authUserInfo = (AuthUserInfo) authentication.getPrincipal();

            // 生成token
            this.generationToken(authUserInfo, request);
            return authUserInfo;
        } catch (AuthenticationException e) {
            ResponseUtils.loginFailThrows(e);
        } catch (Exception e) {
            throw new SecurityException(e.getMessage());
        }
        throw new SecurityAuthException(AuthHttpStatus.LOGIN_FAIL);
    }

    /**
     * 退出登录删除redis缓存
     *
     * @throws SecurityAuthException
     */
    @Override
    public void logout() throws SecurityAuthException {
        //2 token不为空，移除token，从redis删除token
        String token = TokenUtils.getToken();
        if (token != null) {
            redisUtils.del(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
        } else {
            throw new SecurityAuthException(AuthHttpStatus.LOGOUT_FAIL.getCode(), AuthHttpStatus.LOGOUT_FAIL.getMessage());
        }

    }

    @Override
    public void saveToken(String token, OnlineUser onlineUser) {
        onlineUser.setHasAdmin(TokenUtils.hasRoleAdmin());
        redisUtils.set(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token), onlineUser, securityProperties.getExpireTime());
    }

    /**
     * 查询全部数据
     *
     * @param filterUserId 是否根据用户Id过滤
     * @return
     */
    @Override
    public List<OnlineUser> getOnlineUserAllByUserId(Object filterUserId) {
        List<String> keys = redisUtils.scan(securityProperties.getCacheOnlineUserInfoKeyPrefix() + "*");
        Collections.reverse(keys);
        List<OnlineUser> onlineUsers = new ArrayList<>();
        for (String key : keys) {
            OnlineUser onlineUser = redisUtils.get(key);
            if (onlineUser == null) {
                continue;
            }
            if (!StrUtils.isEmpty(filterUserId)) {
                if (filterUserId.equals(onlineUser.getId())) {
                    onlineUsers.add(onlineUser);
                }
            } else {
                onlineUsers.add(onlineUser);
            }
        }
        onlineUsers.sort((o1, o2) -> o2.getRefreshTime().compareTo(o1.getRefreshTime()));
        return onlineUsers;
    }

    /**
     * 获取用户完整的信息(除密码外)
     *
     * @param
     * @return Object 需要自行转Entity对象
     */
    @Override
    public OnlineUser getOnlineUserInfo() {
        String token = TokenUtils.getToken();
        if (StrUtils.isEmpty(token)) {
            return null;
        }
        OnlineUser onlineUserInfo = getOne(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
        return onlineUserInfo;
    }

    @Override
    public OnlineUser getOnlineUserInfoByToken(String token) {
        if (StrUtils.isEmpty(token)) {
            return null;
        }
        if (StringUtils.hasText(token) && token.startsWith(securityProperties.getTokenStartWith())) {
            token = token.replace(securityProperties.getTokenStartWith(), "");
        }
        OnlineUser onlineUserInfo = getOne(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
        return onlineUserInfo;
    }

    /**
     * 查询用户
     *
     * @param key /
     * @return /
     */
    @Override
    public OnlineUser getOne(String key) {
        return redisUtils.get(key);
    }

    /**
     * 根据缓存前缀删除缓存
     *
     * @param prefixKey
     * @return
     */
    @Override
    public void deleteCacheByPrefix(String prefixKey) {
        redisUtils.deleteCacheByPrefix(prefixKey);
    }

    @Override
    public List<OnlineUser> getOnlineUserAll() {
        List<OnlineUser> onlineUserList = redisUtils.fetchLike(securityProperties.getCacheOnlineUserInfoKeyPrefix() + "*");
        return onlineUserList;
    }

    @Override
    public void refreshToken(OnlineUser onlineUser) {
        String token = TokenUtils.getToken();
        if (token != null && onlineUser != null) {
            log.debug("token过期时间已刷新");
            onlineUser.setRefreshTime(System.currentTimeMillis());
            redisUtils.set(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token), onlineUser, securityProperties.getExpireTime());
        } else {
            log.error("无法刷新token过期时间，token【{}】onlineUser【{}】", token != null, onlineUser != null);
        }
    }

    /**
     * 修改用户信息强制退出登录
     *
     * @param ids 用户id
     */
    @Override
    @Async
    public void logoutForcibly(List<?> ids) {
        List<OnlineUser> onlineUserAll = getOnlineUserAll();
        onlineUserAll.forEach(onlineUser -> {
            if (ids.contains(onlineUser.getId())) {
                try {
                    String token = CryptoUtils.desDecrypt(onlineUser.getKey(), securityProperties.getDesPassword());
                    redisUtils.del(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        });

    }

    /**
     * 生成token并缓存用户信息
     *
     * @param authUserInfo 用户信息
     * @param request
     */
    @Override
    public void generationToken(AuthUserInfo authUserInfo, HttpServletRequest request) {
        String token = null;
        // 获取自定义token
        token = securityService.getCustomizeToken(authUserInfo);
        if (StrUtils.isEmpty(token)) {
            token = TokenUtils.createToken();
        }
        authUserInfo.setToken(securityProperties.getTokenStartWith() + token);
        // 保存在线信息
        this.tokenSave(authUserInfo, token, request);
        // 检查是否登录过，踢出登录
        if (securityProperties.isSingleLogin()) {
            this.checkLoginOnUser(authUserInfo.getId(), token);
        }
    }

    /**
     * @param userId     用户名
     * @param ignoreToken 生成的token令牌
     */
    private void checkLoginOnUser(Object userId, String ignoreToken) {
        List<OnlineUser> onlineUsers = getOnlineUserAllByUserId(userId);
        if (onlineUsers == null || onlineUsers.isEmpty()) {
            return;
        }
        for (OnlineUser onlineUser : onlineUsers) {
            if (userId.equals(onlineUser.getId())) {
                try {
                    String token = CryptoUtils.desDecrypt(onlineUser.getKey(), securityProperties.getDesPassword());
                    if (!StrUtils.isEmpty(ignoreToken) && !ignoreToken.equals(token)) {
                        // 踢出用户
                        redisUtils.del(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
                    }
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
    }

    /**
     * 保存在线用户信息
     *
     * @param authUserInfo /
     * @param token        /
     * @param request      /
     */
    private void tokenSave(AuthUserInfo authUserInfo, String token, HttpServletRequest request) {

        try {
            // 用户权限赋值
            this.setUserPermission(authUserInfo);
            String ip = StrUtils.getIp(request);
            String browser = StrUtils.getBrowser(request);
            OnlineUser onlineUser = new OnlineUser(authUserInfo.getId(),
                    authUserInfo.getAccount(),
                    null,
                    authUserInfo.getNickname(),
                    browser,
                    ip,
                    CryptoUtils.desEncrypt(token, securityProperties.getDesPassword()),
                    LocalDateTime.now(),
                    System.currentTimeMillis(),
                    securityProperties.getLoginSource(),
                    authUserInfo.getExtendField(),
                    TokenUtils.hasRoleAdmin(authUserInfo.getRoles()),
                    authUserInfo.getRoles(),
                    authUserInfo.getAuthorities(),
                    authUserInfo.getResourcePermissions());
            saveLoginInfo(onlineUser, token);
            request.setAttribute(securityProperties.getHeader(), securityProperties.getTokenStartWith() + token);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new SecurityAuthException(AuthHttpStatus.TOKEN_UNAUTHORIZED.getCode(), AuthHttpStatus.TOKEN_UNAUTHORIZED.getMessage());
        }
    }

    @Override
    public void refreshUserPermission(Object userId) {
        List<OnlineUser> onlineUsers = getOnlineUserAllByUserId(userId);
        if (CollectionUtils.isEmpty(onlineUsers)) {
            return;
        }
        AuthUserInfo authUserInfo = new AuthUserInfo();
        authUserInfo.setId(userId);
        this.setUserPermission(authUserInfo);
        boolean isAdmin = TokenUtils.hasRoleAdmin(authUserInfo.getRoles());
        for (OnlineUser onlineUser : onlineUsers) {
            String token;
            try {
                token = CryptoUtils.desDecrypt(onlineUser.getKey(), securityProperties.getDesPassword());
            } catch (Exception e) {
                throw new SecurityAuthException("刷新用户权限token解密失败");
            }

            onlineUser.setHasAdmin(isAdmin);
            onlineUser.setRoles(authUserInfo.getRoles());
            onlineUser.setAuthorities(authUserInfo.getAuthorities());
            onlineUser.setResourcePermissions(authUserInfo.getResourcePermissions());
            this.saveLoginInfo(onlineUser, token);
        }

    }

    @Override
    public void deleteCacheAll() {
        this.deleteCacheByPrefix(AuthConstant.SYS_RESOURCE_PERMISSION_ALL_CACHE_KEY);
    }

    private void saveLoginInfo(OnlineUser onlineUser, String token) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(onlineUser, token, onlineUser.getAuthorities());
        // 设置登录认证信息到上下文
        SecurityContextHolder.getContext().setAuthentication(authentication);
        redisUtils.set(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token), onlineUser, securityProperties.getExpireTime());
    }

    /**
     * 设计用户权限
     *
     * @param authUserInfo
     */
    private void setUserPermission(AuthUserInfo authUserInfo) {
        Set<String> permissions = new HashSet<>();
        Set<ResourcePermission> resourcePermissions = new HashSet<>();
        // 用户权限列表，根据用户拥有的权限标识与如 @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
        AuthRoleInfo authRoleInfo = securityService.getRolePermissionInfo(authUserInfo.getId());

        for (AuthRoleInfo.BaseRoleInfo role : authRoleInfo.getRoles()) {
            for (ResourcePermission resourcePermission : role.getResourcePermission()) {
                permissions.add(resourcePermission.getPermissionCode());
                resourcePermissions.add(resourcePermission);
            }
        }
        authUserInfo.setRoles(authRoleInfo.getRoles());


        if (permissions.isEmpty()) {
            permissions.add("default");
        }
        authUserInfo.setResourcePermissions(resourcePermissions);
        authUserInfo.setAuthorities(permissions.stream().map(GrantedOfAuthority::new).collect(Collectors.toList()));
    }

}
