package io.githuub.osinn.securitytoken.security;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.CharsetUtil;

import io.githuub.osinn.securitytoken.security.dto.OnlineUser;
import io.githuub.osinn.securitytoken.enums.JwtHttpStatus;
import io.githuub.osinn.securitytoken.service.ISecurityService;
import io.githuub.osinn.securitytoken.starter.SecurityJwtProperties;
import io.githuub.osinn.securitytoken.utils.IpUtils;
import io.githuub.osinn.securitytoken.utils.ResponseUtils;
import io.githuub.osinn.securitytoken.utils.TokenUtils;
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
            ResponseUtils.outWriter(JwtHttpStatus.LOGOUT_SUCCESS.getCode(), JwtHttpStatus.LOGOUT_SUCCESS.getMessage(), null, request, response);
        }
    }


}
