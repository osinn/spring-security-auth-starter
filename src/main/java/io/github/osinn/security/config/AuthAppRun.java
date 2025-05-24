package io.github.osinn.security.config;

import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.ResponseUtils;
import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.security.dto.CustomizeResponseBodyField;
import io.github.osinn.security.utils.SpringContextHolder;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import io.github.osinn.security.utils.RedisUtils;

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
        if (securityProperties.isAppRunDeleteHistoryToken()) {
            log.debug("------>  删除旧token  <------");
            try {
                RedisUtils redisUtils = SpringContextHolder.getBean(RedisUtils.class);
                redisUtils.deleteCacheByPrefix(securityProperties.getCacheOnlineUserInfoKeyPrefix());
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }

        Map<String, String> responseBody = securityProperties.getResponseBody();

        CustomizeResponseBodyField customizeResponseBodyField = new CustomizeResponseBodyField();
        customizeResponseBodyField.setMessageField(responseBody.get("message") == null ? "message" : responseBody.get("message"));
        customizeResponseBodyField.setErrorField(responseBody.get("error") == null ? "error" : responseBody.get("error"));
        customizeResponseBodyField.setCodeField(responseBody.get("code") == null ? "code" : responseBody.get("code"));

        ResponseUtils.customizeResponseBodyField = customizeResponseBodyField;
    }
}
