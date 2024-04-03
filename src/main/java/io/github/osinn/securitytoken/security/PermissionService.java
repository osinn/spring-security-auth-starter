package io.github.osinn.securitytoken.security;

import io.github.osinn.securitytoken.constants.JwtConstant;
import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.security.dto.JwtRoleInfo;
import io.github.osinn.securitytoken.security.dto.OnlineUser;
import io.github.osinn.securitytoken.starter.SecurityJwtProperties;
import io.github.osinn.securitytoken.utils.StrUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.PatternMatchUtils;
import org.springframework.util.StringUtils;

import java.util.Collection;

public class PermissionService {

    private SecurityJwtProperties securityJwtProperties;

    public PermissionService(SecurityJwtProperties securityJwtProperties) {
        this.securityJwtProperties = securityJwtProperties;
    }

    /**
     * 判断接口是否有xxx:xxx权限
     *
     * @param hasPermission 权限，多个以｜分割
     * @return {boolean}
     */
    public boolean hasPermission(String hasPermission) {

        if (!AuthType.CODE.equals(securityJwtProperties.getAuthType())) {
            return true;
        }
        if (StrUtils.isEmpty(hasPermission)) {
            return false;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return false;
        }
        String[] permissionArray = hasPermission.split(JwtConstant.DELIMETER);

        for (String permission : permissionArray) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            boolean anyMatch = permission.contains(JwtConstant.ALL_PERMISSION) || authorities.stream().map(GrantedAuthority::getAuthority).filter(StringUtils::hasText)
                    .anyMatch(x -> PatternMatchUtils.simpleMatch(permission, x));
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
    public boolean hasRoles(String roles) {
        if (StrUtils.isEmpty(roles)) {
            return false;
        }
        String[] roleArray = roles.split(JwtConstant.DELIMETER);
        for (String role : roleArray) {
            if (hasRole(role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断用户是否拥有此角色
     *
     * @param role 角色字符串
     * @return {boolean}
     */
    public boolean hasRole(String role) {
        if (StrUtils.isEmpty(role)) {
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
        for (JwtRoleInfo.BaseRoleInfo sysRole : onlineUser.getRoles()) {
            String roleCode = sysRole.getRoleCode();
            if (!StrUtils.isEmpty(roleCode)) {
                if (JwtConstant.SUPER_ADMIN_ROLE.equals(roleCode) || roleCode.equals(trim(role))) {
                    return true;
                }
            }
        }
        return false;
    }

    private String trim(String str) {
        return (str == null ? "" : str.trim());
    }

}
