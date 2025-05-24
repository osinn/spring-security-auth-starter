package io.github.osinn.security.security.filter;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.SecurityAuthenticationEntryPoint;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.CryptoUtils;
import io.github.osinn.security.utils.StrUtils;
import io.github.osinn.security.utils.TokenUtils;
import io.github.osinn.security.security.dto.SecurityStorage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * token的校验
 * 该类继承自BasicAuthenticationFilter，在doFilterInternal方法中，
 * 如果校验通过，就认为这是一个取得授权的合法请求
 *
 * @author wency_cai
 */
@Slf4j
public class SecurityAuthenticationFilter extends BasicAuthenticationFilter {

    private SecurityProperties securityProperties;

    private IOnlineUserService onlineUserService;

    /**
     * 白名单
     */
    private SecurityStorage securityStorage;

    private SecurityAuthenticationEntryPoint authenticationEntryPoint;

    private ISecurityService securityService;


    public SecurityAuthenticationFilter(AuthenticationManager authenticationManager,
                                        SecurityStorage securityStorage,
                                        IOnlineUserService onlineUserService,
                                        SecurityProperties securityProperties,
                                        SecurityAuthenticationEntryPoint authenticationEntryPoint,
                                        ISecurityService securityService) {
        super(authenticationManager);
        this.securityStorage = securityStorage;
        this.onlineUserService = onlineUserService;
        this.securityProperties = securityProperties;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.securityService = securityService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            this.checkAuthentication(request, response);
            chain.doFilter(request, response);
        } catch (AuthenticationException e) {
            this.authenticationEntryPoint.commence(request, response, e);
        } catch (Exception e) {
            log.error(e.getMessage());
            this.authenticationEntryPoint.commence(request, response, new AuthenticationServiceException(AuthHttpStatus.INTERNAL_SERVER_ERROR.getMessage(), new SecurityAuthException(AuthHttpStatus.INTERNAL_SERVER_ERROR)));
        }
    }

    /**
     * 获取令牌进行认证
     *
     * @param request
     */
    private void checkAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // 多环境，效验请求
        if (StringUtils.hasLength(securityProperties.getEnvTag()) && StringUtils.hasLength(securityProperties.getHeaderEnvTagName())) {
            String headerEnvTag = request.getHeader(securityProperties.getHeaderEnvTagName());
            if (!securityProperties.getEnvTag().equals(headerEnvTag)) {
                request.setAttribute(AuthHttpStatus.ENV_TAG_ERROR.name(), AuthHttpStatus.ENV_TAG_ERROR.getMessage());
                throw new AuthenticationServiceException(AuthHttpStatus.ENV_TAG_ERROR.getMessage(), new SecurityAuthException(AuthHttpStatus.ENV_TAG_ERROR));
            }
        }

        boolean anonymousUrs = securityStorage.isAnonymousUri(request);
        //OPTIONS请求或白名单直接放行
        if (request.getMethod().equals(HttpMethod.OPTIONS.toString()) || anonymousUrs) {
            return;
        }

        String token = TokenUtils.getToken(request);
        if (!StrUtils.isEmpty(token) && securityProperties.getIgnoringToken().contains(securityProperties.getTokenStartWith() + token)) {
            OnlineUser onlineUser = onlineUserService.getOne(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
            if (onlineUser != null) {
                request.setAttribute(AuthConstant.ONLINE_USER_ID, onlineUser.getId());
            }
        }

        // 获取令牌并根据令牌获取登录认证信息
        Authentication authentication = this.getAuthenticationFromToken(request);
        // 设置登录认证信息到上下文
        SecurityContextHolder.getContext().setAuthentication(authentication);

        securityService.doFilterBeforeHandler(request, response);

    }

    /**
     * 根据请求令牌获取登录认证信息
     *
     * @return 用户名
     */
    private Authentication getAuthenticationFromToken(HttpServletRequest request) {
        String token = TokenUtils.getToken(request);
        if (StrUtils.isEmpty(token)) {
            request.setAttribute(AuthHttpStatus.TOKEN_EXPIRE.name(), AuthHttpStatus.TOKEN_EXPIRE.getMessage());
            throw new AuthenticationCredentialsNotFoundException(AuthHttpStatus.TOKEN_EXPIRE.getMessage());
        } else {
            // 验证 token 是否存在
            OnlineUser onlineUser = null;
            onlineUser = onlineUserService.getOne(securityProperties.getCacheOnlineUserInfoKeyPrefix() + CryptoUtils.md5DigestAsHex(token));
            if (onlineUser == null) {
                request.setAttribute(AuthHttpStatus.TOKEN_EXPIRE.name(), AuthHttpStatus.TOKEN_EXPIRE.getMessage());
                throw new AuthenticationCredentialsNotFoundException(AuthHttpStatus.TOKEN_EXPIRE.getMessage());
            } else {
                try {
                    request.setAttribute(AuthConstant.ONLINE_USER_ID, onlineUser.getId());
                    UsernamePasswordAuthenticationToken authentication = this.getAuthentication(onlineUser, token);
                    // 是否刷新token缓存过期时间
                    if (securityProperties.isDynamicRefreshToken()) {
                        Long loginTime = onlineUser.getRefreshTime();
                        boolean flagRefreshTime = updateRefreshTimeIfNeeded(loginTime, securityProperties.getExpireTime());
                        if (flagRefreshTime) {
                            // 过期时间过半刷新token缓存过期时间
                            TokenUtils.refreshToken(onlineUser);
                        }
                    }
                    return authentication;
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                    request.setAttribute(AuthHttpStatus.TOKEN_EXPIRE.name(), AuthHttpStatus.TOKEN_EXPIRE.getMessage());
                    throw new AuthenticationCredentialsNotFoundException(AuthHttpStatus.TOKEN_EXPIRE.getMessage());
                }

            }
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(OnlineUser onlineUser, String token) {
        return new UsernamePasswordAuthenticationToken(onlineUser, token, onlineUser.getAuthorities());
    }

    private boolean updateRefreshTimeIfNeeded(long refreshTime, long expireTime) {
        //秒转换为毫秒
        long expireMillis = expireTime * 1000;
        long nowTime = System.currentTimeMillis();
        // 计算时间差
        long timeDifference = nowTime - refreshTime;
        // 判断续租时间阈值
        return timeDifference > expireMillis * securityProperties.getExpireRatio();
    }

}
