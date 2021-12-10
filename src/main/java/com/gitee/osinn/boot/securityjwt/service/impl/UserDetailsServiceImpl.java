package com.gitee.osinn.boot.securityjwt.service.impl;

import com.gitee.osinn.boot.securityjwt.exception.SecurityJwtException;
import com.gitee.osinn.boot.securityjwt.security.dto.JwtUser;
import com.gitee.osinn.boot.securityjwt.service.ISecurityService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.gitee.osinn.boot.securityjwt.enums.JwtHttpStatus;

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

        JwtUser jwtUser = findUser(account);
        return jwtUser;

    }

    private JwtUser findUser(String account) {

        Object user = null;
        try {
            user = securityService.loadUserByUsername(account);
        } catch (SecurityJwtException | DisabledException | LockedException e) {
            throw e;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new SecurityJwtException(JwtHttpStatus.INTERNAL_SERVER_ERROR.getCode(), JwtHttpStatus.INTERNAL_SERVER_ERROR.getMessage());
        }

        if (user == null) {
            throw new UsernameNotFoundException(JwtHttpStatus.NOT_FOUND_ACCOUNT.getMessage());
        }

        JwtUser jwtUser;
        try {
            jwtUser = new JwtUser();
            BeanUtils.copyProperties(user, jwtUser);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new UsernameNotFoundException(JwtHttpStatus.NOT_FOUND_ACCOUNT.getMessage());

        }
//        if (!jwtUser.isEnabled()) {
//            throw new DisabledException(JwtHttpStatus.DISABLED_ACCOUNT.getMessage());
//        }
//        if (!jwtUser.isAccountNonLocked()) {
//            throw new LockedException(JwtHttpStatus.LOCK_ACCOUNT.getMessage());
//        }

        return jwtUser;
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
