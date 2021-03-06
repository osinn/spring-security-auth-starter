package com.gitee.osinn.boot.securityjwt.service.impl;

import com.gitee.osinn.boot.securityjwt.constants.JwtConstant;
import com.gitee.osinn.boot.securityjwt.enums.JwtHttpStatus;
import com.gitee.osinn.boot.securityjwt.exception.SecurityJwtException;
import com.gitee.osinn.boot.securityjwt.security.dto.AuthUser;
import com.gitee.osinn.boot.securityjwt.security.dto.JwtRoleInfo;
import com.gitee.osinn.boot.securityjwt.security.dto.JwtUser;
import com.gitee.osinn.boot.securityjwt.security.dto.OnlineUser;
import com.gitee.osinn.boot.securityjwt.service.IOnlineUserService;
import com.gitee.osinn.boot.securityjwt.service.ISecurityCaptchaCodeService;
import com.gitee.osinn.boot.securityjwt.service.ISecurityService;
import com.gitee.osinn.boot.securityjwt.starter.SecurityJwtProperties;
import com.gitee.osinn.boot.securityjwt.utils.*;
import lombok.extern.slf4j.Slf4j;
import net.dreamlu.mica.ip2region.core.Ip2regionSearcher;
import net.dreamlu.mica.ip2region.core.IpInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
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
    private Ip2regionSearcher regionSearcher;

    @Autowired
    private ISecurityCaptchaCodeService securityCaptchaCodeService;

    @Override
    public JwtUser customAuth(Object principal, HttpServletRequest request) {
        JwtUser jwtUser = securityService.customAuth(principal);

        if (jwtUser == null) {
            return null;
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(jwtUser, null, jwtUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        // 生成token
        this.generationToken(jwtUser, request);
        return jwtUser;
    }

    @Override
    public JwtUser auth(AuthUser authUser, HttpServletRequest request) {

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
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 生成令牌
        JwtUser jwtUser = (JwtUser) authentication.getPrincipal();

        // 生成token
        this.generationToken(jwtUser, request);
        return jwtUser;

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
        onlineUsers.sort((o1, o2) -> o2.getLoginTime().compareTo(o1.getLoginTime()));
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
    public void deleteCacheAll() {
        redisUtils.deleteCacheByPrefix(JwtConstant.ONLINE_TOKEN_KEY);
        redisUtils.deleteCacheByPrefix(JwtConstant.ONLINE_USER_INFO_KEY);
        redisUtils.deleteCacheByPrefix(JwtConstant.RESOURCE_PERMISSION);
    }

    @Override
    public List<OnlineUser> fetchOnlineUserAll() {
        List<OnlineUser> onlineUserList = redisUtils.fetchLike(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + "*");
        return onlineUserList;
    }

    @Override
    public void refreshToken() {
        String token = TokenUtils.getToken();
        if (token != null) {
            redisUtils.expire(
                    JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token),
                    securityJwtProperties.getTokenValidityInSeconds());
        } else {
            log.warn("token 不存在无法刷新过期时间");
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
        IpInfo ipInfo = regionSearcher.btreeSearch(ip);
        String address = JwtConstant.REGION;
        if (ipInfo != null) {
            String addressAndIsp = ipInfo.getAddressAndIsp();
            if (!StrUtils.isEmpty(addressAndIsp)) {
                address = addressAndIsp.replace("中国", "");
            }
        }
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
                    address,
                    DesEncryptUtils.desEncrypt(token),
                    new Date(),
                    jwtUser.getRoles(),
                    jwtUser.getAuthorities());

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
        // 用户权限列表，根据用户拥有的权限标识与如 @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
        JwtRoleInfo jwtRoleInfo = securityService.fetchRolePermissionInfo(jwtUser.getId());
        jwtUser.setRoles(jwtRoleInfo.getRoles());
        List<String> frolePermissionList = jwtRoleInfo.getPermissions();
        if (frolePermissionList != null) {
            permissions.addAll(frolePermissionList);
        }

        if (permissions.isEmpty()) {
            permissions.add("default");
        }

        jwtUser.setAuthorities(permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

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
