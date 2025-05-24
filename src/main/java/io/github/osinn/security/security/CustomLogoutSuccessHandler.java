package io.github.osinn.security.security;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.CharsetUtil;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.enums.AuthHttpStatus;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.IpUtils;
import io.github.osinn.security.utils.ResponseUtils;
import io.github.osinn.security.utils.TokenUtils;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;


/**
 * 自定义退出拦截器
 *
 * @author wency_cai
 */
@Slf4j
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Resource
    private ISecurityService securityService;

    @Resource
    private SecurityProperties securityProperties;

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
        if(securityProperties.isLoginOutResponse()) {
            response.setCharacterEncoding(CharsetUtil.UTF_8);
            String path = request.getRequestURI();
            ResponseUtils.outWriter(AuthHttpStatus.LOGOUT_SUCCESS.getCode(), AuthHttpStatus.LOGOUT_SUCCESS.getMessage(), null, path, request, response);
        }
    }


}
