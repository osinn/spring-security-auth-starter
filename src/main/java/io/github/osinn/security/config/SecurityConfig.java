package io.github.osinn.security.config;

import io.github.osinn.security.security.*;
import io.github.osinn.security.security.filter.CustomAuthorizationFilter;
import io.github.osinn.security.security.filter.MyRequestFilter;
import io.github.osinn.security.service.IApiAuthService;
import io.github.osinn.security.service.IOnlineUserService;
import io.github.osinn.security.starter.SecurityJwtProperties;
import io.github.osinn.security.annotation.AnonymousAccess;
import io.github.osinn.security.annotation.AutoAccess;
import io.github.osinn.security.security.dto.SecurityStorage;
import io.github.osinn.security.security.filter.JwtAuthenticationFilter;
import io.github.osinn.security.service.ISecurityService;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPattern;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;


/**
 * @author wency_cai
 */
@Configuration
@EnableWebSecurity
@Order(Ordered.HIGHEST_PRECEDENCE)
@EnableMethodSecurity(
        prePostEnabled = true, // 启用注解授权
        securedEnabled = true,
        jsr250Enabled = true
)
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Autowired
    private SecurityJwtProperties securityJwtProperties;

    @Autowired
    private SecurityStorage securityStorage;

    @Autowired
    private ISecurityService securityService;

    @Autowired
    private IApiAuthService apiAuthService;

    @Autowired
    private IOnlineUserService onlineUserService;


    @Value("${server.servlet.context-path:}")
    private String contextPath;

    /**
     * 权限白名单urls
     */
    private Set<String> anonymousUrs = Sets.newHashSet();

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        // WebSecurityCustomizer是一个类似于Consumer<WebSecurity>的接口，函数接受一个WebSecurity类型的变量，无返回值
//        // 此处使用lambda实现WebSecurityCustomizer接口，web变量的类型WebSecurity，箭头后面可以对其进行操作
//        // 使用requestMatchers()代替antMatchers()
//        return (web) -> web.ignoring().requestMatchers("/ignore1", "/ignore2");
//    }

//    @Bean
//    public WebSecurityCustomizer webSecurity() {
//        return (web) -> web
//                .ignoring().requestMatchers("/testWebSecurity");
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                           AuthenticationManagerBuilder authenticationManagerBuilder,
                                           RequestMappingHandlerMapping requestMappingHandlerMapping,
                                           PasswordEncoder passwordEncoder,
                                           ISecurityService securityService) throws Exception {


        // 搜寻匿名标记 url： @AnonymousAccess
        Map<RequestMappingInfo, HandlerMethod> handlerMethodMap = requestMappingHandlerMapping.getHandlerMethods();
        Set<String> anonymousUrls = new HashSet<>();
        Set<String> authUrlsPrefix = new HashSet<>();

        // 默认拦截 /** 下所有路径
        authUrlsPrefix.add("/*");
        if ("/".equals(contextPath)) {
            contextPath = "";
        }
        for (Map.Entry<RequestMappingInfo, HandlerMethod> infoEntry : handlerMethodMap.entrySet()) {
            HandlerMethod handlerMethod = infoEntry.getValue();

            // 基于注解排除路径
            AnonymousAccess anonymousAccess = handlerMethod.getMethodAnnotation(AnonymousAccess.class);
            if (null != anonymousAccess) {
                if (infoEntry.getKey().getPatternsCondition() == null) {
                    assert infoEntry.getKey().getPathPatternsCondition() != null;
                    Set<PathPattern> patterns = infoEntry.getKey().getPathPatternsCondition().getPatterns();
                    patterns.forEach(p -> {
                        anonymousUrls.add(contextPath + p.getPatternString());
                    });
                } else {
                    Set<String> patterns = infoEntry.getKey().getPatternsCondition().getPatterns();
                    patterns.forEach(p -> {
                        anonymousUrls.add(contextPath + p);
                    });
                }

            } else {
                AutoAccess autoAccess = handlerMethod.getMethodAnnotation(AutoAccess.class);
                if (null != autoAccess) {
                    Set<String> patterns = infoEntry.getKey().getPatternsCondition().getPatterns();
                    patterns.forEach(p -> {
                        authUrlsPrefix.add(contextPath + p);
                    });
                }
            }
        }
        // 基于配置url排除路径
        Set<String> ignoringUrls = securityJwtProperties.getIgnoringUrls();
        anonymousUrls.addAll(ignoringUrls);

        // 基于配置url拦截路径
        Set<String> authUrls = securityJwtProperties.getAuthUrlsPrefix();
        authUrlsPrefix.addAll(authUrls);

        //        anonymousUrlList.add("");

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
                "/file/*",
                "/druid/*"
        };
        anonymousUrs.addAll(Lists.newArrayList(staticFileUrl));
        anonymousUrs.addAll(Lists.newArrayList(pageAnonymousUrl));
        anonymousUrs.addAll(Lists.newArrayList(anonymousUrls));
        securityStorage.setPermissionAnonymousUrlList(anonymousUrs);


        if (securityJwtProperties.isDisableHttpBasic()) {
            // 禁用Http Basic
            httpSecurity.httpBasic().disable();
        }
        if (securityJwtProperties.isDisableCsrf()) {
            // 禁用 CSRF
            httpSecurity.csrf().disable();
        }

//.ignoring().requestMatchers("/ignore1", "/ignore2");
        httpSecurity
                // 禁用默认登录页
                .formLogin().disable()
                // 禁用默认登出页
                .logout().disable()
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> {
                    e.accessDeniedHandler(jwtAccessDeniedHandler);
                    e.authenticationEntryPoint(authenticationEntryPoint);
                })
                .authorizeHttpRequests(authorize -> {
                            try {
                                authorize
                                        // 匿名
                                        // 静态资源等等
                                        .requestMatchers(
                                                HttpMethod.GET,
                                                staticFileUrl
                                        ).permitAll()
                                        .requestMatchers("/favicon.ico", "/resources/**", "/error").permitAll()
                                        .requestMatchers(pageAnonymousUrl).permitAll()
                                        .requestMatchers(HttpMethod.OPTIONS, "/*").permitAll()
                                        .requestMatchers(anonymousUrs.toArray(new String[0])).permitAll()
                                        .requestMatchers(authUrlsPrefix.toArray(new String[0])).permitAll()
                                        // 其余都需要认证
                                        .anyRequest()
                                        // 自定义拦截路径
                                        .authenticated();
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .httpBasic(withDefaults());
        httpSecurity.addFilterBefore(new JwtAuthenticationFilter(authenticationManagerBuilder.getObject(),
                        securityStorage,
                        apiAuthService,
                        onlineUserService,
                        securityJwtProperties,
                        authenticationEntryPoint,
                        securityService),
                UsernamePasswordAuthenticationFilter.class);

        httpSecurity.addFilterBefore(new MyRequestFilter(securityJwtProperties.isEnableCors(), securityJwtProperties.isEnableXss(), securityJwtProperties.getAuthType()), CorsFilter.class);
        httpSecurity.addFilterAfter(new CustomAuthorizationFilter(new AccessDecisionAuthorizationManager(accessDecisionManager(), securityMetadataSource())), AuthorizationFilter.class);
        return httpSecurity.build();
    }

    //    @Bean
//    public AccessDecisionManagerAuthorizationManagerAdapter authorizationManagerAdapter() {
//        return new AccessDecisionManagerAuthorizationManagerAdapter(accessDecisionManager(), securityMetadataSource());
//    }
//
//    @Bean
//    public CustomExceptionTranslationFilter customExceptionTranslationFilter() {
//        CustomExceptionTranslationFilter customExceptionTranslationFilter = new CustomExceptionTranslationFilter(authenticationEntryPoint);
//        customExceptionTranslationFilter.setAccessDeniedHandler(accessDecisionManager());
//        return customExceptionTranslationFilter;
//    }

    @Bean
    public CustomAccessDecisionManager accessDecisionManager() {
        return new CustomAccessDecisionManager(securityStorage,
                apiAuthService,
                securityJwtProperties.getAuthType());
    }

    private CustomSecurityMetadataSource securityMetadataSource() {
        CustomSecurityMetadataSource securityMetadataSource = new CustomSecurityMetadataSource(
                securityService,
                securityStorage,
                securityJwtProperties.getAuthType());
        return securityMetadataSource;
    }

}
