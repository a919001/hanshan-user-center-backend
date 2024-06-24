package com.hanshan.hanshanusercenterbackend.model.request;

import lombok.Data;

import java.io.Serializable;

/**
 * 用户注册请求体
 * @author hanshan
 */
@Data
public class UserRegisterRequest implements Serializable {

    private String username;

    private String password;

    private String checkPassword;

    private String phone;

    private String verifyCode;

    private static final long serialVersionUID = 7845234370377479074L;
}
