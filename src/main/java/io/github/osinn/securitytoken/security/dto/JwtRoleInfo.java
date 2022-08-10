package io.github.osinn.securitytoken.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

/**
 * @author wency_cai
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtRoleInfo implements Serializable {

    /**
     * 用户拥有的角色
     */
    private List<BaseRoleInfo> roles;

    /**
     * 菜单权限标识或用户角色集合，@PreAuthorize 注解只作用在auth-type: CODE
     * 用户权限列表，根据用户拥有的权限标识例如： @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
     *
     */
    private List<String> permissions = Collections.emptyList();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BaseRoleInfo implements Serializable {

        /**
         * 角色id
         */
        private Object id;

        /**
         * 角色名称
         */
        private String name;

        /**
         * 角色编码，角色是管理员还是普通用户或其他
         * 约定值为 admin 是超级管理员角色
         */
        private String roleCode;
    }
}
