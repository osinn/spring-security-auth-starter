package io.github.osinn.securitytoken.config;

import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.security.*;
import io.github.osinn.securitytoken.service.IApiAuthService;
import io.github.osinn.securitytoken.service.IOnlineUserService;
import io.github.osinn.securitytoken.starter.SecurityJwtProperties;
import io.github.osinn.securitytoken.annotation.AnonymousAccess;
import io.github.osinn.securitytoken.annotation.AutoAccess;
import io.github.osinn.securitytoken.security.dto.SecurityStorage;
import io.github.osinn.securitytoken.security.filter.JwtAuthenticationFilter;
import io.github.osinn.securitytoken.security.filter.MyRequestFilter;
import io.github.osinn.securitytoken.service.ISecurityService;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
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
@EnableGlobalMethodSecurity(
        prePostEnabled = true, // 启用注解授权
        securedEnabled = true,
        jsr250Enabled = true
)
@Order(Ordered.HIGHEST_PRECEDENCE)
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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity,
                                           AuthenticationManagerBuilder authenticationManagerBuilder,
                                           RequestMappingHandlerMapping requestMappingHandlerMapping) throws Exception {


        // 搜寻匿名标记 url： @AnonymousAccess
        Map<RequestMappingInfo, HandlerMethod> handlerMethodMap = requestMappingHandlerMapping.getHandlerMethods();
        Set<String> anonymousUrls = new HashSet<>();
        Set<String> authUrlsPrefix = new HashSet<>();

        // 默认拦截 /** 下所有路径
        authUrlsPrefix.add("/**");
        if ("/".equals(contextPath)) {
            contextPath = "";
        }
        for (Map.Entry<RequestMappingInfo, HandlerMethod> infoEntry : handlerMethodMap.entrySet()) {
            HandlerMethod handlerMethod = infoEntry.getValue();

            // 基于注解排除路径
            AnonymousAccess anonymousAccess = handlerMethod.getMethodAnnotation(AnonymousAccess.class);

//            if (AuthType.SERVICE.equals(securityJwtProperties.getAuthType())) {
//                // 基于服务名称请求业务接口权限认证
//                APIHandlerMethod apiAnnotation = handlerMethod.getMethodAnnotation(APIHandlerMethod.class);
//                if (apiAnnotation != null) {
//                    String serviceMethod = StrUtils.isEmpty(apiAnnotation.serviceMethod()) ? handlerMethod.getMethod().getName() : apiAnnotation.serviceMethod();
//                    apiHandlerMethods.put(apiAnnotation.service() + JwtConstant.POINT + serviceMethod, apiAnnotation);
//                }
//            }
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
                "/**/*.html",
                "/**/*.css",
                "/**/*.js",
                "/webSocket/**"
        };
        // 不需要认证的的白名单uri
        String[] pageAnonymousUrl = {
                "/swagger-ui.html",
                "/swagger-resources/**",
                "/webjars/**",
                "/*/api-docs",
                "/avatar/**",
                "/file/**",
                "/druid/**"
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
        httpSecurity

//                .addFilter(new JwtAuthenticationFilter(authenticationManagerBuilder.getObject(),
//                        securityStorage,
//                        apiAuthService,
//                        onlineUserService,
//                        securityJwtProperties))
                // 授权异常
                .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // 防止iframe 造成跨域
                .and()
                .headers()
                .frameOptions()
                .disable()

                // 不创建会话
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                // 静态资源等等
                .antMatchers(
                        HttpMethod.GET,
                        staticFileUrl
                ).permitAll()
                .antMatchers(pageAnonymousUrl).permitAll()
                // 放行OPTIONS请求
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // 自定义匿名访问所有url放行 ： 允许匿名和带权限以及登录用户访问
                .antMatchers(anonymousUrls.toArray(new String[0])).permitAll()
                // 所有请求都需要认证
                .anyRequest().authenticated()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O fsi) {
                        if (!AuthType.CODE.equals(securityJwtProperties.getAuthType())) {
                            fsi.setAccessDecisionManager(accessDecisionManager());
                        }
//                        fsi.setAccessDecisionManager(accessDecisionManager());
//                        fsi.setSecurityMetadataSource(mySecurityMetadataSource(fsi.getSecurityMetadataSource()));
                        return fsi;
                    }
                })
                .and()
                .requestMatchers()
                // 自定义拦截路径
                .antMatchers(authUrlsPrefix.toArray(new String[0]))
                .and().logout().logoutUrl("/logout").logoutSuccessHandler(customLogoutSuccessHandler()).permitAll();

        httpSecurity.addFilterBefore(new JwtAuthenticationFilter(authenticationManagerBuilder.getObject(),
                        securityStorage,
                        apiAuthService,
                        onlineUserService,
                        securityJwtProperties,
                        authenticationEntryPoint),
                UsernamePasswordAuthenticationFilter.class);
        httpSecurity.addFilterBefore(new MyRequestFilter(securityJwtProperties.isEnableCors(), securityJwtProperties.isEnableXss(), securityJwtProperties.getAuthType()), CorsFilter.class);
        //单用户登录，如果有一个登录了，同一个用户在其他地方不能登录
        //httpSecurity.sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true);

        return httpSecurity.build();
    }


    @Bean
    public CustomAccessDecisionManager accessDecisionManager() {
        return new CustomAccessDecisionManager(securityStorage,
                securityService,
                apiAuthService,
                securityJwtProperties.getAuthType());
    }

    @Bean
    public CustomLogoutSuccessHandler customLogoutSuccessHandler() {
        return new CustomLogoutSuccessHandler();
    }

//
//    @Bean
//    public CustomSecurityMetadataSource mySecurityMetadataSource(FilterInvocationSecurityMetadataSource filterInvocationSecurityMetadataSource) {
//        CustomSecurityMetadataSource securityMetadataSource = new CustomSecurityMetadataSource(filterInvocationSecurityMetadataSource,
//                permissionAnonymousUri,
//                ISecurityService);
//        return securityMetadataSource;
//    }

}
