package com.hanshan.hanshanusercenterbackend.common;

import lombok.Data;

import java.util.Date;

/**
 * 验证码对象
 * @author hanshan
 */
@Data
public class VerifyCodeHolder {
    private String code;
    private Date generationTime;

    public VerifyCodeHolder(String code) {
        this.code = code;
        this.generationTime = new Date();
    }
}