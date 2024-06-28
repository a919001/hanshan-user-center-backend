package com.hanshan.hanshanusercenterbackend.model.request;

import lombok.Data;

import java.io.Serializable;
import java.util.Date;

/**
 * 用户信息更新请求体
 * @author hanshan
 */
@Data
public class UserUpdateInfoRequest implements Serializable {

    private String nickname;

    private Integer gender;

    private Date birthday;

    private String region;

    private String signature;

    private static final long serialVersionUID = 7845234370377479074L;
}
