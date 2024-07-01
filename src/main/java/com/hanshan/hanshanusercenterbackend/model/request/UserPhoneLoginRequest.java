package com.hanshan.hanshanusercenterbackend.model.request;

import lombok.Data;

import java.io.Serializable;

/**
 * 手机号登录请求体
 * @author hanshan
 */
@Data
public class UserPhoneLoginRequest implements Serializable {

    private String phone;

    private String verifyCode;

    private static final long serialVersionUID = 7845234370377479074L;
}
