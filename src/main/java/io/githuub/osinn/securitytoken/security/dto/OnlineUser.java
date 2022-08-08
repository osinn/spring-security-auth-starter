package io.githuub.osinn.securitytoken.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

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
     * ip归属地
     */
    private String address;

    /**
     * DES加密token
     */
    private String key;

    /**
     * 登录时间
     */
    private Date loginTime;

    /**
     * 用户角色
     */
    private List<JwtRoleInfo.BaseRoleInfo> roles = Collections.emptyList();
    //
//    @JsonIgnore
//    @JSONField(serialize = false)
    private Collection<GrantedAuthority> authorities = Collections.emptyList();

    public List<String> getAuthority() {
        return this.authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
    }
}
