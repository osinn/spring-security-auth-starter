//package top.itczw.framework.boot.api.securityjwt.utils;
//
//import com.google.common.base.CaseFormat;
//import com.google.common.collect.Lists;
//import com.google.common.collect.Maps;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.stereotype.Component;
//import org.springframework.util.ObjectUtils;
//import org.springframework.util.StringUtils;
//import top.itczw.framework.boot.api.securityjwt.exception.SecurityJwtException;
//
//import javax.sql.DataSource;
//import java.lang.reflect.Field;
//import java.sql.*;
//import java.util.List;
//import java.util.Map;
//import java.util.concurrent.ConcurrentHashMap;
//
///**
// * @author wency_cai
// * @description: 数据库查询工具类
// **/
//@Slf4j
//@Component
//public class DbUtils {
//
//    private static String QUERY_SQL = "select * from user where username = ?";
//
//    private DataSource dataSource;
//
//    private Connection connection = null;
//    private PreparedStatement ps = null;
//    private ResultSet resultSet = null;
//
//    public DbUtils(DataSource dataSource) {
//        this.dataSource = dataSource;
//    }
//
//    public ResultSet findUserByName(String name) throws SQLException {
//        ResultSet resultSet = executeSQL(QUERY_SQL, name);
//        return resultSet;
//    }
//
//    public Map<String, Object> findUserById(String userId) {
//
//        int where = QUERY_SQL.lastIndexOf("where");
//        String sql = QUERY_SQL.substring(0, where) + " where id = ?";
//
//        try {
//            this.resultSet = executeSQL(sql, userId);
//            Map<String, Object> resultMap = new ConcurrentHashMap<>();
//            ResultSetMetaData metaData = resultSet.getMetaData();
//            int columnCount = metaData.getColumnCount();
//            while (resultSet.next()) {
//                for (int index = 1; index < columnCount + 1; index++) {
//                    String columnName = metaData.getColumnName(index);
//                    Object columnValue = resultSet.getObject(columnName);
//                    resultMap.put(columnName, columnValue == null ? "" : columnValue);
//                }
//            }
//            return resultMap;
//        } catch (SQLException e) {
//            log.error(e.getMessage(), e);
//        } finally {
//            this.close();
//        }
//
//        return Maps.newHashMap();
//
//    }
//
//    private ResultSet executeSQL(String sql, String parameter) throws SQLException {
//
//        connection = dataSource.getConnection();
//        ps = connection.prepareStatement(sql);
//        ps.setString(1, parameter);
//
//        resultSet = ps.executeQuery();
//
//        return resultSet;
//    }
//
//    public void close() {
//        try {
//            if (this.resultSet != null) {
//                this.resultSet.close();
//            }
//            if (this.ps != null) {
//                this.ps.close();
//
//            }
//            if (this.connection != null) {
//                this.connection.close();
//
//            }
//        } catch (SQLException ignore) {
//            log.error(ignore.getMessage(), ignore);
//        }
//
//    }
//
//    /**
//     * 自定义根据用户名查询用户sql
//     *
//     * @param querySql
//     */
//    public void setQuerySql(String querySql) {
//        if (!StringUtils.isEmpty(querySql)) {
//            QUERY_SQL = querySql;
//        }
//    }
//
//
//    /**
//     * 将 ResultSet 结果转bean
//     *
//     * @param resultClass
//     * @param rs
//     * @param <T>
//     * @return
//     * @throws SecurityJwtException
//     */
//    public <T> T wrapperOneResult(Class<T> resultClass, ResultSet rs) throws SecurityJwtException {
//        Object resultObj = null;
//        Map<String, Object> userInfoMap = new ConcurrentHashMap<>();
//        try {
//            ResultSetMetaData metaData = rs.getMetaData();
//            int columnCount = metaData.getColumnCount();
//            Field[] fields = resultClass.getDeclaredFields();
//            List<String> fieldNames = Lists.newArrayList();
//            for (int i = 0; i < fields.length; i++) {
//                if (fields[i].getName() != null && !"".equals(fields[i].getName())) {
//                    fieldNames.add(fields[i].getName());
//                }
//            }
//            while (rs.next()) {
//                resultObj = resultClass.newInstance();
//                for (int index = 1; index < columnCount + 1; index++) {
//                    String columnName = metaData.getColumnName(index);
//                    Object columnValue = rs.getObject(columnName);
//
//                    if (columnValue != null) {
//                        String fieldName = columnNameToFieldName(columnName);
//                        // 判断bean是否有此字段
//                        if (!fieldNames.contains(fieldName)) {
//                            continue;
//                        }
//
//                        if ("enabled".equals(fieldName)) {
//                            if (columnValue instanceof Long || columnValue instanceof Integer) {
//                                if (Long.valueOf(columnValue + "") == 1) {
//                                    columnValue = true;
//                                } else {
//                                    columnValue = false;
//                                }
//                            } else if (!(columnValue instanceof Boolean)) {
//                                continue;
//                            }
//                        }
//
//                        if ("id".equals(fieldName)) {
//                            if (columnValue instanceof Long || columnValue instanceof Integer) {
//                                columnValue = String.valueOf(columnValue);
//                            }
//                        }
//
//                        Field field;
//                        try {
//                            field = resultClass.getDeclaredField(fieldName);
//                        } catch (NoSuchFieldException e) {
//                            log.error(e.getMessage(), e);
//                            try {
//                                field = resultClass.getSuperclass().getDeclaredField(fieldName);
//                            } catch (NoSuchFieldException e2) {
//                                log.error(e2.getMessage(), e2);
//                                throw new SecurityJwtException("No such filed ： " + fieldName);
//                            }
//                        }
//                        field.setAccessible(true);
//                        field.set(resultObj, columnValue);
//                    }
//                }
//            }
//
//        } catch (Exception e) {
//            log.error(e.getMessage(), e);
//            throw new SecurityJwtException("Encapsulation result set object encounters exception information：" + e.getMessage(), e);
//        }
//        return ObjectUtils.isEmpty(resultObj) ? null : (T) resultObj;
//    }
//
//    /**
//     * 下划线转驼峰
//     *
//     * @param columnName
//     * @return
//     */
//    private String columnNameToFieldName(String columnName) {
//        String fieldName = columnName.toLowerCase();
//        return CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_CAMEL, fieldName);
//    }
//}
