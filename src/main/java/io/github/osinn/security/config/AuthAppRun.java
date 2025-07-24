package io.github.osinn.security.config;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.AuthResponseUtils;
import io.github.osinn.security.security.dto.CustomizeResponseBodyField;
import io.github.osinn.security.utils.SpringContextHolder;
import io.github.osinn.security.utils.TokenUtils;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import io.github.osinn.security.utils.RedisUtils;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import java.util.Map;

/**
 * @author wency_cai
 **/
@Slf4j
public class AuthAppRun implements CommandLineRunner {

    @Resource
    private SecurityProperties securityProperties;

    @Override
    public void run(String... args) {
        RedisConnectionFactory factory = SpringContextHolder.getBean(RedisConnectionFactory.class);
        IOnlineUserService onlineUserService = SpringContextHolder.getBean(IOnlineUserService.class);
        RedisUtils.initAfterPropertiesSet(factory);
        TokenUtils.initAfterPropertiesSet(securityProperties, onlineUserService);
        if (securityProperties.isAppRunDeleteHistoryToken()) {
            log.debug("------>  删除旧token  <------");
            try {
                RedisUtils.deleteCacheByPrefix(securityProperties.getCodeKey(AuthConstant.CACHE_ONLINE_USER_INFO_KEY_PREFIX));
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }

        Map<String, String> responseBody = securityProperties.getResponseBody();

        CustomizeResponseBodyField customizeResponseBodyField = new CustomizeResponseBodyField();
        customizeResponseBodyField.setMessageField(responseBody.get("message") == null ? "message" : responseBody.get("message"));
        customizeResponseBodyField.setErrorField(responseBody.get("error") == null ? "error" : responseBody.get("error"));
        customizeResponseBodyField.setCodeField(responseBody.get("code") == null ? "code" : responseBody.get("code"));

        AuthResponseUtils.customizeResponseBodyField = customizeResponseBodyField;

        SecurityProperties.IpIntercept ipIntercept = securityProperties.getIpIntercept();
        RedisUtils.set(securityProperties.getCodeKey(AuthConstant.CACHE_IP_INTERCEPT_ALLOW), ipIntercept.getAllow());
        RedisUtils.set(securityProperties.getCodeKey(AuthConstant.CACHE_IP_INTERCEPT_DENY), ipIntercept.getDeny());
    }
}
