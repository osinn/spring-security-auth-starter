package io.github.osinn.security.security;

import io.github.osinn.security.constants.AuthConstant;
import io.github.osinn.security.enums.AuthType;
import io.github.osinn.security.security.dto.AuthRoleInfo;
import io.github.osinn.security.security.dto.OnlineUser;
import io.github.osinn.security.starter.SecurityProperties;
import io.github.osinn.security.utils.StrUtils;
import io.github.osinn.security.utils.TokenUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.PatternMatchUtils;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.List;

/**
 * 描述
 *
 * @author wency_cai
 */
public class PermissionService {

    private final SecurityProperties securityProperties;

    public PermissionService(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /**
     * 判断接口是否有xxx:xxx权限
     *
     * @param hasPermission 权限，多个以｜分割
     * @return {boolean}
     */
    public boolean hasPermission(String hasPermission) {

        String token = TokenUtils.getToken();
        if (token != null && securityProperties.getIgnoringToken().contains(securityProperties.getTokenStartWith() + token)) {
            // 白名单token放行
            return true;
        }

        if (!AuthType.CODE.equals(securityProperties.getAuthType())) {
            return true;
        }
        if (StrUtils.isEmpty(hasPermission)) {
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        String[] permissionArray = hasPermission.split(AuthConstant.DELIMETER);

        for (String permission : permissionArray) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            boolean anyMatch = authorities.stream().map(GrantedAuthority::getAuthority).filter(StringUtils::hasText)
                    .anyMatch(x -> PatternMatchUtils.simpleMatch(permission.trim(), x));
            if (anyMatch) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断用户是否具有以下任意一个角色
     *
     * @param roles 角色，多个以｜分割
     * @return {boolean}
     */
    public boolean hasRole(String roles) {
        if (StrUtils.isEmpty(roles)) {
            return false;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        OnlineUser onlineUser = (OnlineUser) authentication.getPrincipal();
        if (onlineUser == null || StrUtils.isEmpty(onlineUser.getRoles())) {
            return false;
        }

        List<AuthRoleInfo.BaseRoleInfo> onlineUserRoles = onlineUser.getRoles();
        if (StrUtils.isEmpty(onlineUserRoles)) {
            return false;
        }

        String[] roleArray = roles.split(AuthConstant.DELIMETER);
        for (String role : roleArray) {
            return onlineUserRoles.stream().map(AuthRoleInfo.BaseRoleInfo::getRoleCode).anyMatch(x -> x.equals(role.trim()));
        }
        return false;
    }
}
