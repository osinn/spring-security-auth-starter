package io.github.osinn.security.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 在线用户信息
 *
 * @author wency_cai
 */
@EqualsAndHashCode
@Data
@AllArgsConstructor
@NoArgsConstructor
public class OnlineUser implements Serializable {

    /**
     * 用户id
     */
    private Object id;

    /**
     * 登录账号
     */
    private String account;

    /**
     * 密码
     */
    private String password;

    /**
     * 昵称
     */
    private String nickname;

    /**
     * 浏览器
     */
    private String browser;

    /**
     * ip地址
     */
    private String ip;

    /**
     * DES加密token
     */
    private String key;

    /**
     * 登录时间
     */
    private Date loginTime;

    /**
     * 刷新时间
     */
    private Date refreshTime;

    /**
     * 登陆来源，可根据需要使用
     */
    private String loginSource;

    /**
     * 扩展字段
     */
    private Object extendField;

    /**
     * 是否是管理员
     */
    private boolean hasAdmin;

    /**
     * 用户角色
     */
    private List<JwtRoleInfo.BaseRoleInfo> roles = Collections.emptyList();
    //
//    @JsonIgnore
    private Collection<? extends GrantedOfAuthority> authorities = Collections.emptyList();

    /**
     * 资源权限
     */
    @JsonIgnore
    private Collection<ResourcePermission> resourcePermissions = Collections.emptyList();

    public List<String> getAuthority() {
        return this.authorities.stream().map(GrantedOfAuthority::getAuthority).collect(Collectors.toList());
    }

    public <T> T getId() {
        return (T) id;
    }
}
