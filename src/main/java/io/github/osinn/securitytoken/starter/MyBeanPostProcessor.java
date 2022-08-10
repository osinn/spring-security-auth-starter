package io.github.osinn.securitytoken.starter;

import io.github.osinn.securitytoken.annotation.API;
import io.github.osinn.securitytoken.annotation.APIMethodPermission;
import io.github.osinn.securitytoken.constants.JwtConstant;
import io.github.osinn.securitytoken.enums.AuthType;
import io.github.osinn.securitytoken.security.dto.SecurityStorage;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 处理需要忽略的Mapper
 *
 * @author wency_cai
 */
public class MyBeanPostProcessor implements BeanPostProcessor {

    private SecurityStorage securityStorage;


    public MyBeanPostProcessor(SecurityStorage securityStorage, boolean apiService, AuthType authType) {
        this.securityStorage = securityStorage;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        API apiAnnotation = bean.getClass().getAnnotation(API.class);
        if (apiAnnotation != null) {
            Map<String, API> apiMap = securityStorage.getApiMap();
            if (apiMap == null) {
                apiMap = new ConcurrentHashMap<>();
            }
            apiMap.put(apiAnnotation.service(), apiAnnotation);
            securityStorage.setApiMap(apiMap);


            Method[] methods = bean.getClass().getMethods();
            for (Method method : methods) {
                // 基于服务名称请求业务接口权限认证
                APIMethodPermission apiMethodPermission = method.getAnnotation(APIMethodPermission.class);
                if (apiMethodPermission != null) {
                    Map<String, APIMethodPermission> apiMethodPermissions = securityStorage.getApiMethodPermissions();
                    if (apiMethodPermissions == null) {
                        apiMethodPermissions = new ConcurrentHashMap<>();
                    }
                    apiMethodPermissions.put(apiAnnotation.service() + JwtConstant.POINT + method.getName(), apiMethodPermission);
                    apiMap.put(apiAnnotation.service() + JwtConstant.POINT + method.getName(), apiAnnotation);
                    securityStorage.setApiMethodPermissions(apiMethodPermissions);
                }
            }
        }
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }
}
