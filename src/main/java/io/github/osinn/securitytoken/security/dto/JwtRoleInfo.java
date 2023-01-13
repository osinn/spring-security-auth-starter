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

        /**
         * 扩展字段
         */
        private Object extendField;


        /**
         * 资源权限
         */
        private List<ResourcePermission> resourcePermission = Collections.emptyList();
    }
}
