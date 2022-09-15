package io.github.osinn.securitytoken.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * 授权资源，内部是根据访问资源路径(uriPath)匹配请求的uri得到permissionCode来判断用户是否有权限访问
 * uriPath -> /api/getUser
 * permissionCode -> ROLE_ANONYMOUS
 *
 * @author wency_cai
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class ResourcePermission implements Serializable {

    /**
     * 访问资源路径
     */
    private String uriPath;

    /**
     * 菜单权限标识或用户角色集合，@PreAuthorize 注解只作用在auth-type: CODE
     * 用户权限列表，根据用户拥有的权限标识例如： @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
     */
    private String permissionCode;

    /**
     * 菜单名称【可选】，在没有权限情况下，如果空只提示“权限不足”，否则带上菜单名称
     */
    private String menuName;
}
