package io.github.osinn.security.service.impl;

import io.github.osinn.security.exception.SecurityAuthException;
import io.github.osinn.security.security.dto.AuthUserInfo;
import io.github.osinn.security.service.ISecurityService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import io.github.osinn.security.enums.AuthHttpStatus;

import java.lang.reflect.Field;


/**
 * @author wency_cai
 */
@Slf4j
@Service("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {


    private ISecurityService securityService;

    public UserDetailsServiceImpl(ISecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public UserDetails loadUserByUsername(String account) {

        log.debug("-------->  loadUserByUsername  <--------");

        return findUser(account);

    }

    private AuthUserInfo findUser(String account) {

        AuthUserInfo authUserInfo = null;
        try {
            authUserInfo = securityService.loadUserByUsername(account);
        } catch (SecurityAuthException | DisabledException | LockedException e) {
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new SecurityAuthException(AuthHttpStatus.INTERNAL_SERVER_ERROR.getCode(), AuthHttpStatus.INTERNAL_SERVER_ERROR.getMessage());
        }

        if (authUserInfo == null) {
            throw new UsernameNotFoundException(AuthHttpStatus.NOT_FOUND_ACCOUNT.getMessage());
        }

        return authUserInfo;
    }

    /**
     * 根据属性名获取属性值
     *
     * @param fieldName
     * @param object
     * @return
     */
    private Object getFieldValueByFieldName(String fieldName, Object object) throws Exception {
        Field field = object.getClass().getDeclaredField(fieldName);
        //设置对象的访问权限，保证对private的属性的访问
        field.setAccessible(true);
        return field.get(object);
    }
}
