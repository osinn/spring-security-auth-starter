package io.github.osinn.securitytoken.security.filter;

import io.github.osinn.securitytoken.constants.JwtConstant;
import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.enums.JwtHttpStatus;
import io.github.osinn.securitytoken.exception.SecurityJwtException;
import io.github.osinn.securitytoken.security.JwtAuthenticationEntryPoint;
import io.github.osinn.securitytoken.security.dto.OnlineUser;
import io.github.osinn.securitytoken.service.IApiAuthService;
import io.github.osinn.securitytoken.service.IOnlineUserService;
import io.github.osinn.securitytoken.service.ISecurityService;
import io.github.osinn.securitytoken.starter.SecurityJwtProperties;
import io.github.osinn.securitytoken.utils.DesEncryptUtils;
import io.github.osinn.securitytoken.utils.StrUtils;
import io.github.osinn.securitytoken.utils.TokenUtils;
import io.github.osinn.securitytoken.security.dto.SecurityStorage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * token的校验
 * 该类继承自BasicAuthenticationFilter，在doFilterInternal方法中，
 * 从http头的Authorization 项读取token数据，然后用Jwts包提供的方法校验token的合法性。
 * 如果校验通过，就认为这是一个取得授权的合法请求
 *
 * @author wency_cai
 */
@Slf4j
public class JwtAuthenticationFilter extends BasicAuthenticationFilter {

    private SecurityJwtProperties securityJwtProperties;

    private IOnlineUserService onlineUserService;

    /**
     * 白名单
     */
    private SecurityStorage securityStorage;

    private IApiAuthService apiAuthService;

    private JwtAuthenticationEntryPoint authenticationEntryPoint;

    private ISecurityService securityService;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   SecurityStorage securityStorage,
                                   IApiAuthService apiAuthService,
                                   IOnlineUserService onlineUserService,
                                   SecurityJwtProperties securityJwtProperties,
                                   JwtAuthenticationEntryPoint authenticationEntryPoint,
                                   ISecurityService securityService) {
        super(authenticationManager);
        this.securityStorage = securityStorage;
        this.apiAuthService = apiAuthService;
        this.onlineUserService = onlineUserService;
        this.securityJwtProperties = securityJwtProperties;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.securityService = securityService;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        try {
            this.checkAuthentication(request, response);
            chain.doFilter(request, response);
        } catch (AuthenticationException e) {
            log.error(e.getMessage(), e);
            this.authenticationEntryPoint.commence(request, response, e);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            this.authenticationEntryPoint.commence(request, response, new AuthenticationServiceException(JwtHttpStatus.INTERNAL_SERVER_ERROR.getMessage(), new SecurityJwtException(JwtHttpStatus.INTERNAL_SERVER_ERROR)));
        }
    }

    /**
     * 获取令牌进行认证
     *
     * @param request
     */
    private void checkAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // 多环境，效验请求
        if (StringUtils.hasLength(securityJwtProperties.getEnvTag()) && StringUtils.hasLength(securityJwtProperties.getHeaderEnvTagName())) {
            String headerEnvTag = request.getHeader(securityJwtProperties.getHeaderEnvTagName());
            if (!securityJwtProperties.getEnvTag().equals(headerEnvTag)) {
                request.setAttribute(JwtHttpStatus.ENV_TAG_ERROR.name(), JwtHttpStatus.ENV_TAG_ERROR.getMessage());
                throw new AuthenticationServiceException(JwtHttpStatus.ENV_TAG_ERROR.getMessage(), new SecurityJwtException(JwtHttpStatus.ENV_TAG_ERROR));
            }
        }

        boolean anonymousUrs = securityStorage.isAnonymousUri(request);
        //OPTIONS请求或白名单直接放行
        if (request.getMethod().equals(HttpMethod.OPTIONS.toString()) || anonymousUrs) {
            return;
        }

        String token = TokenUtils.getToken(request);
        if (!StrUtils.isEmpty(token) && securityJwtProperties.getIgnoringToken().contains(securityJwtProperties.getTokenStartWith() + token)) {
            OnlineUser onlineUser = onlineUserService.getOne(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
            if(onlineUser != null) {
                request.setAttribute(JwtConstant.ONLINE_USER_ID, onlineUser.getId());
                request.setAttribute(JwtConstant.ONLINE_USER_INFO_KEY, onlineUser);
            }
        } else {
            if (AuthType.SERVICE.equals(securityJwtProperties.getAuthType())) {
                // 判断是否为匿名访问服务
                boolean anonymousService = apiAuthService.checkAnonymousService(request);
                if (anonymousService) {
                    return;
                }
            }

            // 获取令牌并根据令牌获取登录认证信息
            Authentication authentication = this.getAuthenticationFromToken(request);
            // 设置登录认证信息到上下文
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }


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
            request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), JwtHttpStatus.TOKEN_EXPIRE.getMessage());
            throw new AuthenticationCredentialsNotFoundException(JwtHttpStatus.TOKEN_EXPIRE.getMessage());
        } else {
            // 验证 token 是否存在
            OnlineUser onlineUser = null;
            onlineUser = onlineUserService.getOne(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
            if (onlineUser == null) {
                request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), JwtHttpStatus.TOKEN_EXPIRE.getMessage());
                throw new AuthenticationCredentialsNotFoundException(JwtHttpStatus.TOKEN_EXPIRE.getMessage());
            } else {
                try {
                    request.setAttribute(JwtConstant.ONLINE_USER_ID, onlineUser.getId());
                    UsernamePasswordAuthenticationToken authentication = this.getAuthentication(onlineUser, token);
                    // 是否刷新token缓存过期时间
                    if (securityJwtProperties.isDynamicRefreshToken()) {
                        Date loginTime = onlineUser.getRefreshTime();
                        if (loginTime != null && (System.currentTimeMillis() - loginTime.getTime()) >= (securityJwtProperties.getTokenValidityInSeconds() * 1000) / 2) {
                            // 过期时间过半刷新token缓存过期时间
                            TokenUtils.refreshToken(onlineUser);
                        }
                    }
                    request.setAttribute(JwtConstant.ONLINE_USER_INFO_KEY, onlineUser);
                    return authentication;
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                    request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), JwtHttpStatus.TOKEN_EXPIRE.getMessage());
                    throw new AuthenticationCredentialsNotFoundException(JwtHttpStatus.TOKEN_EXPIRE.getMessage());
                }

            }
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(OnlineUser onlineUser, String token) {
        return new UsernamePasswordAuthenticationToken(onlineUser, token, onlineUser.getAuthorities());
    }

}
