package io.github.osinn.security.config;

import io.github.osinn.security.security.*;
import io.github.osinn.security.security.filter.CustomAuthorizationFilter;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.annotation.AuthIgnore;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.security.filter.SecurityAuthenticationFilter;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.utils.RedisUtils;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPattern;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * @author wency_cai
 */
@Configuration
@EnableWebSecurity
@Order(Ordered.HIGHEST_PRECEDENCE)
@EnableMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true
)
public class SecurityConfig {

    @Resource
    private SecurityAuthenticationEntryPoint authenticationEntryPoint;

    @Resource
    private SecurityAccessDeniedHandler securityAccessDeniedHandler;

    @Resource
    private SecurityProperties securityProperties;

    @Resource
    private SecurityStorage securityStorage;

    @Resource
    private ISecurityService securityService;

    @Resource
    private IOnlineUserService onlineUserService;

    @Resource
    private RedisUtils redisUtils;

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    @Resource
    private RequestMappingHandlerMapping requestMappingHandlerMapping;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                           AuthenticationManagerBuilder authenticationManagerBuilder,
                                           ISecurityService securityService) throws Exception {

        Map<RequestMappingInfo, HandlerMethod> handlerMethodMap = requestMappingHandlerMapping.getHandlerMethods();
        Set<String> anonymousUrls = new HashSet<>();

        for (Map.Entry<RequestMappingInfo, HandlerMethod> infoEntry : handlerMethodMap.entrySet()) {
            HandlerMethod handlerMethod = infoEntry.getValue();

            // 基于注解排除路径
            AuthIgnore authIgnore = handlerMethod.getMethodAnnotation(AuthIgnore.class);
            if (null != authIgnore) {
                if (infoEntry.getKey().getPatternsCondition() == null) {
                    if (infoEntry.getKey().getPathPatternsCondition() != null) {
                        Set<PathPattern> patterns = infoEntry.getKey().getPathPatternsCondition().getPatterns();
                        patterns.forEach(p -> {
                            anonymousUrls.add(contextPath + p.getPatternString());
                        });
                    }
                } else {
                    Set<String> patterns = infoEntry.getKey().getPatternsCondition().getPatterns();
                    patterns.forEach(p -> {
                        anonymousUrls.add(contextPath + p);
                    });
                }

            }
        }
        // 基于配置url排除路径
        Set<String> ignoringUrls = securityProperties.getIgnoringUrls();
        anonymousUrls.addAll(ignoringUrls);

        // 基于配置url拦截路径
        Set<String> authUrlsPrefix = securityProperties.getAuthorizedUrlPrefix();

        // 不需要认证的静态资源
        String[] staticFileUrl = {
                "/*.html",
                "/*/*.html",
                "/*/*.css",
                "/*/*.js",
                "/webSocket/*"
        };
        // 不需要认证的的白名单uri
        String[] pageAnonymousUrl = {
                "/swagger-ui.html",
                "/swagger-resources/*",
                "/webjars/*",
                "/*/api-docs",
                "/avatar/*",
                "/druid/*"
        };

        // 权限白名单urls
        anonymousUrls.addAll(Set.of(staticFileUrl));
        anonymousUrls.addAll(Set.of(pageAnonymousUrl));
        securityStorage.setPermissionAnonymousUrlList(anonymousUrls);


        if (securityProperties.isDisableHttpBasic()) {
            // 禁用Http Basic
            httpSecurity.httpBasic().disable();
        }
        if (securityProperties.isDisableCsrf()) {
            // 禁用 CSRF
            httpSecurity.csrf().disable();
        }

        httpSecurity
                // 禁用默认登录页
                .formLogin().disable()
                // 禁用默认登出页
                .logout().disable()
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> {
                    e.accessDeniedHandler(securityAccessDeniedHandler);
                    e.authenticationEntryPoint(authenticationEntryPoint);
                })
                .authorizeHttpRequests(authorize -> {
                            try {
                                authorize
                                        // 匿名
                                        // 静态资源等等
                                        .requestMatchers(HttpMethod.GET, staticFileUrl).permitAll()
                                        .requestMatchers(pageAnonymousUrl).permitAll()
                                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                        .requestMatchers(anonymousUrls.toArray(new String[0])).permitAll()
                                        .requestMatchers(authUrlsPrefix.toArray(new String[0])).permitAll()
                                        // 其余都需要认证
                                        .anyRequest()
                                        .authenticated();
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                );
        httpSecurity.addFilterBefore(new SecurityAuthenticationFilter(authenticationManagerBuilder.getObject(),
                        securityStorage,
                        onlineUserService,
                        securityProperties,
                        authenticationEntryPoint,
                        securityService),
                UsernamePasswordAuthenticationFilter.class);

        httpSecurity.addFilterAfter(new CustomAuthorizationFilter(new AccessDecisionAuthorizationManager<>(accessDecisionManager(), securityMetadataSource())), AuthorizationFilter.class);
        return httpSecurity.build();
    }

    @Bean
    public CustomAccessDecisionManager accessDecisionManager() {
        return new CustomAccessDecisionManager(securityStorage, securityProperties.getAuthType());
    }

    private CustomSecurityMetadataSource securityMetadataSource() {
        return new CustomSecurityMetadataSource(
                securityService,
                securityStorage,
                securityProperties,
                redisUtils,
                securityProperties.getAuthType());
    }

    @Bean("pms")
    public PermissionService permissionService() {
        return new PermissionService(securityProperties);
    }

}
