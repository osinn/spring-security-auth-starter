package io.githuub.osinn.securitytoken.starter;

import io.githuub.osinn.securitytoken.security.JwtAccessDeniedHandler;
import io.githuub.osinn.securitytoken.security.JwtAuthenticationEntryPoint;
import io.githuub.osinn.securitytoken.security.dto.SecurityStorage;
import io.githuub.osinn.securitytoken.service.IApiAuthService;
import io.githuub.osinn.securitytoken.service.ISecurityCaptchaCodeService;
import io.githuub.osinn.securitytoken.service.impl.ApiAuthServiceImpl;
import io.githuub.osinn.securitytoken.service.impl.SecurityCaptchaCodeServiceImpl;
import io.githuub.osinn.securitytoken.utils.PasswordEncoderUtils;
import io.githuub.osinn.securitytoken.utils.SpringContextHolder;
import org.springframework.beans.factory.annotation.Autowired;
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
@ComponentScan("io.githuub.osinn.securitytoken")
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

}