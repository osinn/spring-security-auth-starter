package io.github.osinn.securitytoken.security;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.CharsetUtil;

import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.security.dto.OnlineUser;
import io.github.osinn.securitytoken.enums.JwtHttpStatus;
import io.github.osinn.securitytoken.service.ISecurityService;
import io.github.osinn.securitytoken.starter.SecurityJwtProperties;
import io.github.osinn.securitytoken.utils.IpUtils;
import io.github.osinn.securitytoken.utils.ResponseUtils;
import io.github.osinn.securitytoken.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 自定义退出拦截器
 *
 * @author wency_cai
 */
@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Autowired
    private ISecurityService securityService;

    @Autowired
    private SecurityJwtProperties securityJwtProperties;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OnlineUser loginUser = TokenUtils.fetchOnlineUserInfo();
        if (loginUser != null) {
            String ipAddress = IpUtils.getHostIp(request);
            log.info("ip：{}， 账号：{}，在{}退出了系统，在线时长：{}",
                    ipAddress,
                    loginUser.getAccount(),
                    DateUtil.now(),
                    DateUtil.formatBetween(loginUser.getLoginTime(), DateUtil.date()));
            // 这里可以做入库日志处理 recordLogoutLog;
            securityService.logoutBeforeHandler(request, response, loginUser);
            TokenUtils.deleteToken();
        }
        if(securityJwtProperties.isLoginOutResponse()) {
            response.setCharacterEncoding(CharsetUtil.UTF_8);
            String path;
            if (AuthType.SERVICE.equals(securityJwtProperties.getAuthType())) {
                path = securityService.getServiceName(request);
            } else {
                path = request.getRequestURI();
            }
            ResponseUtils.outWriter(JwtHttpStatus.LOGOUT_SUCCESS.getCode(), JwtHttpStatus.LOGOUT_SUCCESS.getMessage(), null, path, request, response);
        }
    }


}
