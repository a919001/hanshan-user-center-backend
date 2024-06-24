package com.hanshan.hanshanusercenterbackend.model.request;

import lombok.Data;

import java.io.Serializable;

/**
 * 删除用户请求体
 * @author hanshan
 */
@Data
public class UserDeleteRequest implements Serializable {

    private Long id;

    private static final long serialVersionUID = 7845234370377479074L;
}
