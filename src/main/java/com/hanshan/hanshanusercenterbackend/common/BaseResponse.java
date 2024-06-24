package com.hanshan.hanshanusercenterbackend.common;

import lombok.Data;

import java.io.Serializable;

/**
 * 通用返回类
 * @author hanshan
 * @param <T>
 */
@Data
public class BaseResponse<T> implements Serializable {

    private int code;

    private String message;

    private T data;

    public BaseResponse(int code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

    public BaseResponse(int code, T data) {
        this.code = code;
        this.message = "";
        this.data = data;
    }

    public BaseResponse(ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
        this.data = null;
    }
}
