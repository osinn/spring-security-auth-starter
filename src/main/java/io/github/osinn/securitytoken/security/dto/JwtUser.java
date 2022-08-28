package io.github.osinn.securitytoken.security.dto;

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
    private String password;

    /**
     * 权限
     */
    @JsonIgnore
    private Collection<GrantedAuthority> authorities;

    /**
     * 用户角色
     */
    @JsonIgnore
    private List<JwtRoleInfo.BaseRoleInfo> roles = Collections.emptyList();

    private String token;

    public JwtUser() {

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
    public Collection getPermissions() {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }
}
