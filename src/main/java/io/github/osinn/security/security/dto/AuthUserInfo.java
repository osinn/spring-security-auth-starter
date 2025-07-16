package io.github.osinn.security.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * token检验信息
 * 用户账号锁定、禁用等状态自行判断
 *
 * @author wency_cai
 */
@Data
@AllArgsConstructor
public class AuthUserInfo implements UserDetails, Serializable {

    /**
     * 用户ID
     */
    private Object id;

    /**
     * 登录账号
     */
    private String account;

    /**
     * 昵称
     */
    private String nickname;

    @JsonIgnore
    private String password;

    /**
     * 扩展字段
     */
    private Object extendField;

    /**
     * 权限
     */
    @JsonIgnore
    private Collection<? extends GrantedOfAuthority> authorities;

    /**
     * 资源权限
     */
    @JsonIgnore
    private Collection<ResourcePermission> resourcePermissions = Collections.emptyList();

    /**
     * 用户角色
     */
    @JsonIgnore
    private List<AuthRoleInfo.BaseRoleInfo> roles = Collections.emptyList();

    private String token;

    public AuthUserInfo() {

    }

    public AuthUserInfo(Object id, String account, String nickname, String password, Object extendField) {
        this.id = id;
        this.account = account;
        this.nickname = nickname;
        this.password = password;
        this.extendField = extendField;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    @JsonIgnore
    @Override
    public String getUsername() {
        return this.account;
    }

    /**
     * 获取用户拥有的权限
     *
     * @return
     */
    public Collection<? extends GrantedOfAuthority> getPermissions() {
        return authorities;
    }
}
