//package top.itczw.framework.boot.api.securityjwt.security;
//
//import org.springframework.security.access.ConfigAttribute;
//import org.springframework.security.access.SecurityConfig;
//import org.springframework.security.web.FilterInvocation;
//import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
//import org.springframework.util.AntPathMatcher;
//import top.itczw.framework.boot.api.securityjwt.enums.AuthType;
//import top.itczw.framework.boot.api.securityjwt.security.dto.PermissionAnonymousUri;
//import top.itczw.framework.boot.api.securityjwt.security.dto.ResourcePermission;
//import top.itczw.framework.boot.api.securityjwt.service.ISecurityService;
//
//import javax.servlet.http.HttpServletRequest;
//import java.util.Collection;
//import java.util.List;
//
///**
// * 自定安全元数据源
// *
// * @author wency_cai
// */
//public class CustomSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
//
//    private FilterInvocationSecurityMetadataSource superMetadataSource;
//
//    /**
//     * 白名单
//     */
//    private PermissionAnonymousUri permissionAnonymousUri;
//
//    private ISecurityService ISecurityService;
//
//    /**
//     * 默认根据url认证
//     */
//    private AuthType authType = AuthType.URL;
//
//    @Override
//    public Collection<ConfigAttribute> getAllConfigAttributes() {
//        return null;
//    }
//
//    public CustomSecurityMetadataSource(FilterInvocationSecurityMetadataSource expressionBasedFilterInvocationSecurityMetadataSource,
//                                        PermissionAnonymousUri permissionAnonymousUri,
//                                        ISecurityService ISecurityService,
//                                        AuthType authType) {
//        this.superMetadataSource = expressionBasedFilterInvocationSecurityMetadataSource;
//        this.permissionAnonymousUri = permissionAnonymousUri;
//        this.ISecurityService = ISecurityService;
//        this.authType = authType;
//    }
//
//    private final AntPathMatcher antPathMatcher = new AntPathMatcher();
//
//    @Override
//    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
//
//        FilterInvocation fi = (FilterInvocation) object;
//        HttpServletRequest request = fi.getHttpRequest();
//        if (!permissionAnonymousUri.isAnonymousUri(request)) {
//
//            //从数据库加载全部权限配置
//            List<ResourcePermission> resourcePermissionList = ISecurityService.fetchResourcePermissionAll();
//            if (resourcePermissionList != null) {
//                String url = fi.getRequestUrl();
//                for (ResourcePermission resourcePermission : resourcePermissionList) {
//                    if (antPathMatcher.match(resourcePermission.getUriPath(), url)) {
//                        return SecurityConfig.createList(resourcePermission.getPermissionCode());
//                    }
//                }
//            }
//
//        }
//        //  返回代码定义的默认配置
//        return superMetadataSource.getAttributes(object);
//    }
//
//
//    @Override
//    public boolean supports(Class<?> clazz) {
//        return FilterInvocation.class.isAssignableFrom(clazz);
//    }
//
//}