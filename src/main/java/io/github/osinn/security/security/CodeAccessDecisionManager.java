package io.github.osinn.security.security;

import cn.hutool.core.collection.CollUtil;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;


/**
 * 自定义code访问决策
 *
 * @author wency_cai
 */
public class CodeAccessDecisionManager {

    public static boolean decide(Authentication authentication, Collection<ConfigAttribute> configAttributes) {
        // 当系统没有配置权限资源时直接放行
        if (CollUtil.isEmpty(configAttributes)) {
            return true;
        }
        for (ConfigAttribute configAttribute : configAttributes) {
            //将系统访问所需资源与用户拥有资源进行比对
            String needAuthority = configAttribute.getAttribute();
            for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
                if (needAuthority.trim().equals(grantedAuthority.getAuthority())) {
                    return true;
                }
            }
        }
        return false;
    }

}