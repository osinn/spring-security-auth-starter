package io.github.osinn.security.starter;

import io.github.osinn.security.security.SecurityAccessDeniedHandler;
import io.github.osinn.security.security.SecurityAuthenticationEntryPoint;
import io.github.osinn.security.service.ISecurityCaptchaCodeService;
import io.github.osinn.security.service.impl.SecurityCaptchaCodeServiceImpl;
import io.github.osinn.security.utils.PasswordEncoderUtils;
import io.github.osinn.security.utils.SpringContextHolder;
import jakarta.annotation.Resource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * @author wency_cai
 * @description: 描述
 **/
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
@ComponentScan("io.github.osinn.security")
public class SecurityAutoConfigure {

    @Resource
    private SecurityProperties securityProperties;

    @Bean
    @ConditionalOnMissingBean
    public ISecurityCaptchaCodeService securityCaptchaCodeService() {
        return new SecurityCaptchaCodeServiceImpl();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAuthenticationEntryPoint securityAuthenticationEntryPoint() {
        return new SecurityAuthenticationEntryPoint(securityProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityAccessDeniedHandler securityAccessDeniedHandler() {
        return new SecurityAccessDeniedHandler(securityProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderUtils.getPasswordEncoder(securityProperties.getIdForEncode());
    }

    @Bean
    public SpringContextHolder springContextHolder() {
        return new SpringContextHolder();
    }


    @Bean
    GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("");
    }

    @Bean
    @ConditionalOnMissingBean(CorsFilter.class)
    @ConditionalOnProperty(value = SecurityProperties.PREFIX + ".enable-cors", havingValue = "true")
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOriginPatterns(List.of("*"));
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.setMaxAge(10000L);
        source.registerCorsConfiguration("/**", corsConfiguration);
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
