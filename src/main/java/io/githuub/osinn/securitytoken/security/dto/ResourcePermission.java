package io.githuub.osinn.securitytoken.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
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
public class ResourcePermission implements Serializable {

    /**
     * 访问资源路径
     */
    private String uriPath;

    /**
     * 访问资源路径权限编码
     */
    private String permissionCode;

    /**
     * 菜单名称【可选】，在没有权限情况下，如果空只提示“权限不足”，否则带上菜单名称
     */
    private String menuName;
}
