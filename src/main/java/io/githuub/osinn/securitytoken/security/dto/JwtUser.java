package io.githuub.osinn.securitytoken.security.dto;

import com.alibaba.fastjson.annotation.JSONField;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * jwt token检验信息
 * 用户账号锁定、禁用等状态自行判断
 *
 * @author wency_cai
 */
@Data
@AllArgsConstructor
public class JwtUser implements UserDetails, Serializable {

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
    @JSONField(serialize = false)
    private String password;

    /**
     * 权限
     */
    @JsonIgnore
    @JSONField(serialize = false)
    private Collection<GrantedAuthority> authorities;

    /**
     * 用户角色
     */
    @JsonIgnore
    @JSONField(serialize = false)
    private List<JwtRoleInfo.BaseRoleInfo> roles = Collections.emptyList();

    private String token;

    public JwtUser() {

    }

    @JSONField(serialize = false)
    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JSONField(serialize = false)
    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JSONField(serialize = false)
    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JSONField(serialize = false)
    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }

    @JSONField(serialize = false)
    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    @JSONField(serialize = false)
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
    public Collection getPermissions() {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }
}
