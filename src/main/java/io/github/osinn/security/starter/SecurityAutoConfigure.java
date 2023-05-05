package io.github.osinn.security.starter;

import io.github.osinn.security.security.JwtAccessDeniedHandler;
import io.github.osinn.security.security.JwtAuthenticationEntryPoint;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.service.IApiAuthService;
import io.github.osinn.security.service.ISecurityCaptchaCodeService;
import io.github.osinn.security.service.impl.ApiAuthServiceImpl;
import io.github.osinn.security.service.impl.RedissonServiceImpl;
import io.github.osinn.security.service.impl.SecurityCaptchaCodeServiceImpl;
import io.github.osinn.security.utils.PasswordEncoderUtils;
import io.github.osinn.security.utils.SpringContextHolder;
import org.redisson.api.RedissonClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author wency_cai
 * @description: 描述
 **/
@Configuration
@EnableConfigurationProperties(SecurityJwtProperties.class)
@ComponentScan("io.github.osinn.security")
public class SecurityAutoConfigure {

    @Autowired
    private SecurityJwtProperties securityJwtProperties;

    @Bean
    @ConditionalOnMissingBean
    public ISecurityCaptchaCodeService securityCaptchaCodeService() {
        return new SecurityCaptchaCodeServiceImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return new JwtAuthenticationEntryPoint(securityJwtProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAccessDeniedHandler jwtAccessDeniedHandler() {
        return new JwtAccessDeniedHandler(securityJwtProperties);
    }
//
//    @Bean
//    @ConditionalOnMissingBean
//    public CorsFilter corsFilter() {
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        CorsConfiguration config = new CorsConfiguration();
//        config.setAllowCredentials(true);
//        config.addAllowedOrigin("*");
//        config.addAllowedHeader("*");
//        config.addAllowedMethod("*");
//        source.registerCorsConfiguration("/**", config);
//        return new CorsFilter(source);
//    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderUtils.getPasswordEncoder(securityJwtProperties.getIdForEncode());
    }



    @Bean
    public SpringContextHolder springContextHolder() {
        return new SpringContextHolder();
    }


    @Bean
    GrantedAuthorityDefaults grantedAuthorityDefaults() {
        // 去除 ROLE_ 前缀
        return new GrantedAuthorityDefaults("");
    }

    @Bean
    public MyBeanPostProcessor myBeanPostProcessor() {
        return new MyBeanPostProcessor(securityStorage(), securityJwtProperties.isApiService(), securityJwtProperties.getAuthType());
    }

    @Bean
    public SecurityStorage securityStorage() {
        return new SecurityStorage();
    }

    @Bean
    public IApiAuthService apiAuthService() {
        return new ApiAuthServiceImpl(securityJwtProperties.getAuthType(), securityJwtProperties.isApiService());
    }

    @Bean
//    @ConditionalOnBean({RedissonClient.class})
    public RedissonServiceImpl redissonDistributeLocker(RedissonClient redissonClient) {
        RedissonServiceImpl redissonService = new RedissonServiceImpl(redissonClient);
        return redissonService;
    }

}
