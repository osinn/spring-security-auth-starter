package io.github.osinn.security.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

/**
 * 自定义GrantedAuthority
 *
 * @author wency_cai
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class GrantedOfAuthority implements GrantedAuthority {

    private String authority;

    @Override
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

}
