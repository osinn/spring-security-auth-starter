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
        // ??????token
        this.generationToken(jwtUser, request);
        return jwtUser;
    }

    @Override
    public JwtUser auth(AuthUser authUser, HttpServletRequest request) {

        SecurityJwtProperties.CaptchaCode captchaCode = securityJwtProperties.getCaptchaCode();
        if (captchaCode.isEnable()) {
            // ???????????????
            String code = securityCaptchaCodeService.getCaptchaCode(authUser.getUuid());
            // ???????????????
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
        // ????????????
        JwtUser jwtUser = (JwtUser) authentication.getPrincipal();

        // ??????token
        this.generationToken(jwtUser, request);
        return jwtUser;

    }

    /**
     * ??????????????????redis??????
     *
     * @throws SecurityJwtException
     */
    @Override
    public void logout() throws SecurityJwtException {
        //2 token??????????????????token??????redis??????token
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
     * ??????????????????
     *
     * @param filterUserId ??????????????????Id??????
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
     * ???????????????????????????(????????????)
     *
     * @param
     * @return Object ???????????????Entity??????
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
     * ????????????
     *
     * @param key /
     * @return /
     */
    @Override
    public OnlineUser getOne(String key) {
        return redisUtils.get(key);
    }

    /**
     * ??????????????????????????????
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
            log.warn("token ?????????????????????????????????");
        }
    }

    /**
     * ????????????????????????????????????
     *
     * @param ids ??????id
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
     * @param userId     ?????????
     * @param igoreToken ?????????token??????
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
                        // ????????????
                        redisUtils.del(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
                    }
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
    }


    /**
     * ????????????????????????
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
                address = addressAndIsp.replace("??????", "");
            }
        }
        OnlineUser onlineUser = null;
        try {
            // ??????????????????
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
     * ??????????????????
     *
     * @param jwtUser
     */
    private void setUserPermission(JwtUser jwtUser) {
        Set<String> permissions = new HashSet<>();
        // ???????????????????????????????????????????????????????????? @PreAuthorize("hasAuthority('sys:menu:view')") ??????????????????????????????????????????????????????
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
     * ??????token?????????????????????
     *
     * @param jwtUser ????????????
     * @param request
     */
    private void generationToken(JwtUser jwtUser, HttpServletRequest request) {
        String token = null;
        // ???????????????token
        token = securityService.getCustomizeToken(jwtUser);
        if (StrUtils.isEmpty(token)) {
            token = TokenUtils.createToken();
        }
        jwtUser.setToken(securityJwtProperties.getTokenStartWith() + token);
        // ??????????????????
        this.tokenSave(jwtUser, token, request);
        // ????????????????????????????????????
        if (securityJwtProperties.isSingleLogin()) {
            this.checkLoginOnUser(jwtUser.getId(), token);
        }
    }
}
