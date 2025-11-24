package io.github.osinn.security.security;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.security.dto.ResourcePermission;
import io.github.osinn.security.service.ISecurityService;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.PermissionUtils;
import io.github.osinn.security.utils.RedisUtils;
import io.github.osinn.security.utils.StrUtils;
import io.github.osinn.security.utils.TokenUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;


/**
 * @author wency_cai
 */
@Slf4j
public class CustomAccessDecisionManager {

    private SecurityProperties securityProperties;
    private ISecurityService securityService;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public CustomAccessDecisionManager() {

    }

    public CustomAccessDecisionManager(ISecurityService securityService, SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.securityService = securityService;
    }

    public boolean decide(Authentication authentication, Object object) throws AccessDeniedException, InsufficientAuthenticationException {


        HttpServletRequest request = (HttpServletRequest) object;

        List<String> resourcePermission = getResourcePermission(request);
        // 当系统没有配置权限资源时直接放行
        if (CollectionUtils.isEmpty(resourcePermission)) {
            return true;
        }

        if (authentication == null) {
            throw new AccessDeniedException("当前没有访问权限");
        }

        if (authentication.getPrincipal() instanceof OnlineUser onlineUser) {

            Boolean hasRoleAdmin = TokenUtils.hasRoleAdmin(onlineUser.getRoles());
            if (hasRoleAdmin) {
                return true;
            }
        }

        if (AuthType.URL.equals(securityProperties.getAuthType())) {
            if (!resourcePermission.isEmpty()) {
                // 请求路径再权限表中，需要认证权限，否则放行
                boolean authority = false;
                for (String permission : resourcePermission) {
                    //资源比对系统权限
                    if (Objects.equals(permission, request.getRequestURI())) {
                        authority = true;
                        break;
                    }
                }

                return authority;
            }

        }
        return true;
    }

    private List<String> getResourcePermission(HttpServletRequest request) {
        if (PermissionUtils.isAnonymous(securityProperties, request)) {
            return null;
        }

        //从数据库加载全部权限配置
        List<ResourcePermission> resourcePermissionList = this.getSysResourcePermissionAll();

        if (resourcePermissionList != null && !resourcePermissionList.isEmpty()) {
            if (AuthType.CODE.equals(securityProperties.getAuthType())) {
                List<String> permissionCodes = new ArrayList<>();
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    // 对比系统权限资源
                    if (!StrUtils.isEmpty(resourcePermission.getPermissionCode())) {
                        permissionCodes.add(resourcePermission.getPermissionCode());
                    }
                }
                return permissionCodes;
            } else {
                String url = request.getRequestURI();
                for (ResourcePermission resourcePermission : resourcePermissionList) {
                    // 对比系统权限资源
                    if (antPathMatcher.match(resourcePermission.getUriPath(), url)) {
                        return List.of(resourcePermission.getUriPath().trim());
                    }
                }
            }
        }
        return null;
    }

    private List<ResourcePermission> getSysResourcePermissionAll() {
        List<ResourcePermission> resourcePermissionList;
        if (securityProperties.isEnableSysResourcePermissionAll()) {
            resourcePermissionList = RedisUtils.getList(securityProperties.getCodeKey(AuthConstant.SYS_RESOURCE_PERMISSION_ALL_CACHE_KEY));
            if (CollectionUtils.isEmpty(resourcePermissionList)) {
                resourcePermissionList = securityService.getSysResourcePermissionAll();
                RedisUtils.set(securityProperties.getCodeKey(AuthConstant.SYS_RESOURCE_PERMISSION_ALL_CACHE_KEY), resourcePermissionList);
            }
        } else {
            resourcePermissionList = securityService.getSysResourcePermissionAll();
        }

        return resourcePermissionList;
    }


}
