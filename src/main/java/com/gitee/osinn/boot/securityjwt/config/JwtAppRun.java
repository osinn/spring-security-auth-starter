package com.gitee.osinn.boot.securityjwt.config;

import com.gitee.osinn.boot.securityjwt.constants.JwtConstant;
import com.gitee.osinn.boot.securityjwt.starter.SecurityJwtProperties;
import com.gitee.osinn.boot.securityjwt.utils.SpringContextHolder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import com.gitee.osinn.boot.securityjwt.utils.RedisUtils;

/**
 * @author wency_cai
 **/
@Slf4j
public class JwtAppRun implements CommandLineRunner {

    @Autowired
    private SecurityJwtProperties securityService;

    @Override
    public void run(String... args) {
        if (securityService.isAppRunDeleteHistoryToken()) {
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
    }
}
