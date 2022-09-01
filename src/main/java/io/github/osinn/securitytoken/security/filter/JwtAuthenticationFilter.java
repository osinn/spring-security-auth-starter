package io.github.osinn.securitytoken.security.filter;

import io.github.osinn.securitytoken.constants.JwtConstant;
import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.enums.JwtHttpStatus;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

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

    @Autowired
    private SecurityJwtProperties securityJwtProperties;

    @Autowired
    private IOnlineUserService onlineUserService;

    @Autowired
    private ISecurityService securityService;

    /**
     * 白名单
     */
    private SecurityStorage securityStorage;

    @Autowired
    private IApiAuthService apiAuthService;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, SecurityStorage securityStorage) {
        super(authenticationManager);
        this.securityStorage = securityStorage;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        this.checkAuthentication(request);
        chain.doFilter(request, response);
    }

    /**
     * 获取令牌进行认证
     *
     * @param request
     */
    private void checkAuthentication(HttpServletRequest request) {
        boolean anonymousUrs = securityStorage.isAnonymousUri(request);
        //OPTIONS请求或白名单直接放行
        if (request.getMethod().equals(HttpMethod.OPTIONS.toString()) || anonymousUrs) {
            return;
        }
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

    /**
     * 根据请求令牌获取登录认证信息
     *
     * @return 用户名
     */
    private Authentication getAuthenticationFromToken(HttpServletRequest request) {
        String token = TokenUtils.getToken(request);
        String requestUri = request.getRequestURI();
        if (StrUtils.isEmpty(token)) {
            request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "token已过期");
            return null;
        } else {
            // 验证 token 是否存在
            OnlineUser onlineUser = null;
            onlineUser = onlineUserService.getOne(JwtConstant.ONLINE_USER_INFO_KEY_PREFIX + DesEncryptUtils.md5DigestAsHex(token));
            if (onlineUser == null) {
                request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "token已过期");
                return null;
            } else {
                try {
                    UsernamePasswordAuthenticationToken authentication = this.getAuthentication(onlineUser, token);
                    log.debug("set Authentication to security context for '{}', uri: {}", authentication.getName(), requestUri);
                    // 是否刷新token缓存过期时间
                    if (securityJwtProperties.isDynamicRefreshToken()) {
                        Date loginTime = onlineUser.getLoginTime();
                        if (loginTime != null && (System.currentTimeMillis() - loginTime.getTime()) >= (securityJwtProperties.getTokenValidityInSeconds() * 1000) / 2) {
                            // 过期时间过半刷新token缓存过期时间
                            TokenUtils.refreshToken(onlineUser);
                        }
                    }
                    return authentication;
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                    request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "token已过期");
                    return null;
                }

            }
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(OnlineUser onlineUser, String token) {
        return new UsernamePasswordAuthenticationToken(onlineUser, token, onlineUser.getAuthorities());
    }

}