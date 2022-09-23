package io.github.osinn.securitytoken.service.impl;

import com.google.common.collect.Lists;
import io.github.osinn.securitytoken.security.dto.*;
import io.github.osinn.securitytoken.starter.SecurityJwtProperties;
import io.github.osinn.securitytoken.constants.JwtConstant;
import io.github.osinn.securitytoken.enums.JwtHttpStatus;
import io.github.osinn.securitytoken.exception.SecurityJwtException;
import io.github.osinn.securitytoken.service.IOnlineUserService;
import io.github.osinn.securitytoken.service.ISecurityCaptchaCodeService;
import io.github.osinn.securitytoken.service.ISecurityService;
import io.github.osinn.securitytoken.utils.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author wency_cai
 */
@Service
@Slf4j
public class OnlineUserServiceImpl implements IOnlineUserService {

    @Autowired
    private ISecurityService securityService;

    @Autowired
    private SecurityJwtProperties securityJwtProperties;

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    private RedisUtils redisUtils;

    @Autowired
    private ISecurityCaptchaCodeService securityCaptchaCodeService;

    @Override
    public JwtUser customAuth(Object principal, HttpServletRequest request) {
        JwtUser jwtUser = securityService.customAuth(principal);

        if (jwtUser == null) {
            return null;
        }

        // 生成token
        this.generationToken(jwtUser, request);

        return jwtUser;
    }

    @Override
    public JwtUser auth(AuthUser authUser, HttpServletRequest request, HttpServletResponse response) {

        SecurityJwtProperties.CaptchaCode captchaCode = securityJwtProperties.getCaptchaCode();
        if (captchaCode.isEnable()) {
            // 查询验证码
            String code = securityCaptchaCodeService.getCaptchaCode(authUser.getUuid());
            // 清除验证码
            securityCaptchaCodeService.delete(authUser.getUuid());
            if (StrUtils.isEmpty(code)) {
                throw new SecurityJwtException(JwtHttpStatus.NOT_FOUND_CODE.getCode(), JwtHttpStatus.NOT_FOUND_CODE.getMessage());
            }
            if (!code.equalsIgnoreCase(authUser.getCode())) {
                throw new SecurityJwtException(JwtHttpStatus.CODE_UNAUTHORIZED.getCode(), JwtHttpStatus.CODE_UNAUTHORIZED.getMessage());
            }
        }

        String password;
        if (!StrUtils.isEmpty(securityJwtProperties.getRsaPrivateKey())) {
            try {
                password = RsaEncryptUtils.decrypt(authUser.getPassword(), securityJwtProperties.getRsaPrivateKey());

            } catch (Exception e) {
                log.error(e.getMessage(), e);
                throw new SecurityJwtException(JwtHttpStatus.PASSWORD_ERROR.getCode(), JwtHttpStatus.TOKEN_UNAUTHORIZED.getMessage());
            }
        } else {
            password = authUser.getPassword();
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(authUser.getUsername(), password);
        Authentication authentication = null;
        try {
            authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // 生成令牌
            JwtUser jwtUser = (JwtUser) authentication.getPrincipal();

            // 生成token
            this.generationToken(jwtUser, request);
            return jwtUser;
        } catch (AuthenticationException e) {
            ResponseUtils.loginFailThrows(e);
        } catch (Exception e) {
            throw new SecurityException(e.getMessage());
        }
        throw new SecurityJwtException(JwtHttpStatus.LOGIN_FAIL);
    }

    /**
     * 退出登录删除redis缓存
     *
     * @throws SecurityJwtException
     */
    @Override
    public void logout() throws SecurityJwtException {
        //2 token不为空，移除token，从redis删除token
        String token = TokenUtils.getToken();
        if (token != null) {
            redisUtils.del(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
        } else {
            throw new SecurityJwtException(JwtHttpStatus.LOGOUT_FAIL.getCode(), JwtHttpStatus.LOGOUT_FAIL.getMessage());
        }

    }

    @Override
    public void saveToken(String token, OnlineUser onlineUser) {
        redisUtils.set(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token), onlineUser, securityJwtProperties.getTokenValidityInSeconds());
    }

    /**
     * 查询全部数据
     *
     * @param filterUserId 是否根据用户Id过滤
     * @return
     */
    @Override
    public List<OnlineUser> fetchOnlineUserAllByUserId(Object filterUserId) {
        List<String> keys = redisUtils.scan(JwtConstant.ONLINE_TOKEN_KEY + "*");
        Collections.reverse(keys);
        List<OnlineUser> onlineUsers = new ArrayList<>();
        for (String key : keys) {
            OnlineUser onlineUser = redisUtils.get(key, OnlineUser.class);
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
    public OnlineUser fetchOnlineUserCompleteInfo() {
        String token = TokenUtils.getToken();
        if (StrUtils.isEmpty(token)) {
            return null;
        }
        OnlineUser onlineUserInfo = getOne(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
        return onlineUserInfo;
    }

    @Override
    public OnlineUser fetchOnlineUserCompleteInfoByToken(String token) {
        if (StrUtils.isEmpty(token)) {
            return null;
        }
        if (StringUtils.hasText(token) && token.startsWith(securityJwtProperties.getTokenStartWith())) {
            token = token.replace(securityJwtProperties.getTokenStartWith(), "");
        }
        OnlineUser onlineUserInfo = getOne(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
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
        return redisUtils.get(key, OnlineUser.class);
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
    public void deleteCacheAll() {
        redisUtils.deleteCacheByPrefix(JwtConstant.ONLINE_TOKEN_KEY);
        redisUtils.deleteCacheByPrefix(JwtConstant.ONLINE_USER_INFO_KEY);
        redisUtils.deleteCacheByPrefix(JwtConstant.RESOURCE_PERMISSION);
    }

    @Override
    public List<OnlineUser> fetchOnlineUserAll() {
        List<String> onlineUserList = redisUtils.fetchLike(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + "*");
        List<OnlineUser> onlineUsers = Lists.newArrayList();
        for (String onlineUserStr : onlineUserList) {
            OnlineUser onlineUser = GsonMapper.toBean(onlineUserStr, OnlineUser.class);
            onlineUsers.add(onlineUser);
        }
        return onlineUsers;
    }

    @Override
    public void refreshToken(OnlineUser onlineUser) {
        String token = TokenUtils.getToken();
        if (token != null && onlineUser != null) {
            onlineUser.setRefreshTime(new Date());
            redisUtils.set(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token), onlineUser, securityJwtProperties.getTokenValidityInSeconds());
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
    public void editUserInfoForciblyLogout(List<Object> ids) {
        List<OnlineUser> onlineUserAll = fetchOnlineUserAll();
        onlineUserAll.forEach(onlineUser -> {
            if (ids.contains(onlineUser.getId())) {
                try {
                    String token = DesEncryptUtils.desDecrypt(onlineUser.getKey());
                    redisUtils.del(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        });

    }


    /**
     * @param userId     用户名
     * @param igoreToken 生成的token令牌
     */
    private void checkLoginOnUser(Object userId, String igoreToken) {
        List<OnlineUser> onlineUsers = fetchOnlineUserAllByUserId(userId);
        if (onlineUsers == null || onlineUsers.isEmpty()) {
            return;
        }
        for (OnlineUser onlineUser : onlineUsers) {
            if (userId.equals(onlineUser.getId())) {
                try {
                    String token = DesEncryptUtils.desDecrypt(onlineUser.getKey());
                    if (!StrUtils.isEmpty(igoreToken) && !igoreToken.equals(token)) {
                        // 踢出用户
                        redisUtils.del(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
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
     * @param jwtUser /
     * @param token   /
     * @param request /
     */
    private void tokenSave(JwtUser jwtUser, String token, HttpServletRequest request) {
        String ip = StrUtils.getIp(request);
        String browser = StrUtils.getBrowser(request);

        OnlineUser onlineUser = null;
        try {
            // 用户权限赋值
            this.setUserPermission(jwtUser);
            onlineUser = new OnlineUser(jwtUser.getId(),
                    jwtUser.getAccount(),
                    jwtUser.getPassword(),
                    jwtUser.getNickname(),
                    browser,
                    ip,
                    DesEncryptUtils.desEncrypt(token),
                    new Date(),
                    new Date(),
                    securityJwtProperties.getLoginSource(),
                    jwtUser.getRoles(),
                    jwtUser.getAuthorities(),
                    jwtUser.getResourcePermissions());
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(onlineUser, token, onlineUser.getAuthorities());
            // 设置登录认证信息到上下文
            SecurityContextHolder.getContext().setAuthentication(authentication);
            redisUtils.set(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token), onlineUser, securityJwtProperties.getTokenValidityInSeconds());
            request.setAttribute(securityJwtProperties.getHeader(), securityJwtProperties.getTokenStartWith() + token);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new SecurityJwtException(JwtHttpStatus.TOKEN_UNAUTHORIZED.getCode(), JwtHttpStatus.TOKEN_UNAUTHORIZED.getMessage());
        }
    }

    /**
     * 设计用户权限
     *
     * @param jwtUser
     */
    private void setUserPermission(JwtUser jwtUser) {
        Set<String> permissions = new HashSet<>();
        Set<ResourcePermission> resourcePermissions = new HashSet<>();
        // 用户权限列表，根据用户拥有的权限标识与如 @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
        JwtRoleInfo jwtRoleInfo = securityService.fetchRolePermissionInfo(jwtUser.getId());

        for (JwtRoleInfo.BaseRoleInfo role : jwtRoleInfo.getRoles()) {
            for (ResourcePermission resourcePermission : role.getResourcePermission()) {
                permissions.add(resourcePermission.getPermissionCode());
                resourcePermissions.add(resourcePermission);
            }
        }
        jwtUser.setRoles(jwtRoleInfo.getRoles());


        if (permissions.isEmpty()) {
            permissions.add("default");
        }
        jwtUser.setResourcePermissions(resourcePermissions);
        jwtUser.setAuthorities(permissions.stream().map(GrantedOfAuthority::new).collect(Collectors.toList()));

    }

    /**
     * 生成token并缓存用户信息
     *
     * @param jwtUser 用户信息
     * @param request
     */
    private void generationToken(JwtUser jwtUser, HttpServletRequest request) {
        String token = null;
        // 获取自定义token
        token = securityService.getCustomizeToken(jwtUser);
        if (StrUtils.isEmpty(token)) {
            token = TokenUtils.createToken();
        }
        jwtUser.setToken(securityJwtProperties.getTokenStartWith() + token);
        // 保存在线信息
        this.tokenSave(jwtUser, token, request);
        // 检查是否登录过，踢出登录
        if (securityJwtProperties.isSingleLogin()) {
            this.checkLoginOnUser(jwtUser.getId(), token);
        }
    }
}
