package com.gitee.osinn.boot.securityjwt.starter;

import com.gitee.osinn.boot.securityjwt.security.JwtAccessDeniedHandler;
import com.gitee.osinn.boot.securityjwt.security.JwtAuthenticationEntryPoint;
import com.gitee.osinn.boot.securityjwt.security.crypto.Md5Sha512PasswordEncoder;
import com.gitee.osinn.boot.securityjwt.service.ISecurityCaptchaCodeService;
import com.gitee.osinn.boot.securityjwt.service.impl.SecurityCaptchaCodeServiceImpl;
import com.gitee.osinn.boot.securityjwt.utils.PasswordEncoderUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import com.gitee.osinn.boot.securityjwt.utils.SpringContextHolder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author wency_cai
 * @description: 描述
 **/
@Configuration
@EnableConfigurationProperties(SecurityJwtProperties.class)
@ComponentScan("com.gitee.osinn.boot.securityjwt")
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

}
