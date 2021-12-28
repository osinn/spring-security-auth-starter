package com.gitee.osinn.boot.securityjwt.security.filter;

import com.gitee.osinn.boot.securityjwt.annotation.API;
import com.gitee.osinn.boot.securityjwt.constants.JwtConstant;
import com.gitee.osinn.boot.securityjwt.enums.AuthType;
import com.gitee.osinn.boot.securityjwt.enums.JwtHttpStatus;
import com.gitee.osinn.boot.securityjwt.exception.SecurityJwtException;
import com.gitee.osinn.boot.securityjwt.security.dto.OnlineUser;
import com.gitee.osinn.boot.securityjwt.security.dto.SecurityStorage;
import com.gitee.osinn.boot.securityjwt.service.IOnlineUserService;
import com.gitee.osinn.boot.securityjwt.service.ISecurityService;
import com.gitee.osinn.boot.securityjwt.starter.SecurityJwtProperties;
import com.gitee.osinn.boot.securityjwt.utils.DesEncryptUtils;
import com.gitee.osinn.boot.securityjwt.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;

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
            // 判断基于API服务名称请求是否白名单
            Map<String, API> apiServiceMap = securityStorage.getApiServiceMap();
            String serviceName = securityService.getServiceName(request);
            if (StringUtils.isEmpty(serviceName)) {
                throw new SecurityJwtException(JwtHttpStatus.NOT_FOUND.getCode(), "未找到服务名称参数");
            }
            API api = apiServiceMap.get(serviceName);
            if (api == null) {
                throw new SecurityJwtException(JwtHttpStatus.NOT_FOUND.getCode(), "服务不存在");
            }
            if (!api.needLogin()) {
                // 不需要登录认证-放行
                return;
            }
        }

        // 获取令牌并根据令牌获取登录认证信息
        Authentication authentication = this.getAuthenticationeFromToken(request);
        // 设置登录认证信息到上下文
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 是否刷新token缓存过期时间
        if (securityJwtProperties.isDynamicRefreshToken()) {
            TokenUtils.refreshToken();
        }
    }

    /**
     * 根据请求令牌获取登录认证信息
     *
     * @return 用户名
     */
    private Authentication getAuthenticationeFromToken(HttpServletRequest request) {
        String token = TokenUtils.getToken(request);
        String requestUri = request.getRequestURI();
        if (StringUtils.isEmpty(token)) {
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
                    UsernamePasswordAuthenticationToken authentication = this.getAuthentication(onlineUser.getAccount(), onlineUser.getPassword(), token, onlineUser.getAuthorities());
                    log.debug("set Authentication to security context for '{}', uri: {}", authentication.getName(), requestUri);
                    return authentication;
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                    request.setAttribute(JwtHttpStatus.TOKEN_EXPIRE.name(), "token已过期");
                    return null;
                }

            }
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String account, String password, String token, Collection<GrantedAuthority> authorities) {
        User principal = new User(account, password, authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
}