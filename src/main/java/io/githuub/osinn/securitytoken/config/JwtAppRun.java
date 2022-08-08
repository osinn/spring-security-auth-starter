package io.githuub.osinn.securitytoken.config;

import io.githuub.osinn.securitytoken.constants.JwtConstant;
import io.githuub.osinn.securitytoken.security.dto.CustomizeResponseBodyField;
import io.githuub.osinn.securitytoken.starter.SecurityJwtProperties;
import io.githuub.osinn.securitytoken.utils.ResponseUtils;
import io.githuub.osinn.securitytoken.utils.SpringContextHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import io.githuub.osinn.securitytoken.utils.RedisUtils;

import java.util.Map;

/**
 * @author wency_cai
 **/
@Slf4j
public class JwtAppRun implements CommandLineRunner {

    @Autowired
    private SecurityJwtProperties securityJwtProperties;

    @Override
    public void run(String... args) {
        if (securityJwtProperties.isAppRunDeleteHistoryToken()) {
            log.debug("------>  删除旧token  <------");
            try {
                RedisUtils redisUtils = SpringContextHolder.getBean(RedisUtils.class);
                redisUtils.deleteCacheByPrefix(JwtConstant.ONLINE_TOKEN_KEY);
                redisUtils.deleteCacheByPrefix(JwtConstant.ONLINE_USER_INFO_KEY);
                redisUtils.deleteCacheByPrefix(JwtConstant.RESOURCE_PERMISSION);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }

        Map<String, String> responseBody = securityJwtProperties.getResponseBody();

        CustomizeResponseBodyField customizeResponseBodyField = new CustomizeResponseBodyField();
        customizeResponseBodyField.setMessageField(responseBody.get("message") == null ? "message" : responseBody.get("message"));
        customizeResponseBodyField.setErrorField(responseBody.get("error") == null ? "error" : responseBody.get("error"));
        customizeResponseBodyField.setCodeField(responseBody.get("code") == null ? "code" : responseBody.get("code"));

        ResponseUtils.customizeResponseBodyField = customizeResponseBodyField;
    }
}
