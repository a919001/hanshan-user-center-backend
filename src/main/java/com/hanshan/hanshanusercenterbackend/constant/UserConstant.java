package com.hanshan.hanshanusercenterbackend.constant;

/**
 * 用户常量类
 * @author hanshan
 */
public interface UserConstant {
    /**
     * 用户登录态
     */
    String USER_LOGIN_STATE = "userLoginState";

    /**
     * AES密钥
     */
    String AES_KEY = "1234qwer1234qwer";

    /**
     * 默认权限
     */
    int DEFAULT_ROLE = 0;

    /**
     * 管理员权限
     */
    int ADMIN_ROLE = 1;

    /**
     * 验证码过期时间
     */
    long VERIFY_CODE_EXPIRED_TIME = 5 * 60 * 1000L;

    /**
     * 验证码
     */
    String VERIFY_CODE = "verifyCode";
}
