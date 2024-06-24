package com.hanshan.hanshanusercenterbackend.common;

/**
 * 返回工具类
 * @author hanshan
 */
public class ResultUtils {

    /**
     * 成功
     * @param data 响应数据
     * @param <T> 泛型
     * @return 通用响应类
     */
    public static <T> BaseResponse<T> success(T data) {
        return new BaseResponse<>(0, "ok", data);
    }

    /**
     * 失败
     * @param code 失败响应码
     * @param message 精简描述
     * @param <T> null
     * @return 通用响应类
     */
    public static <T> BaseResponse<T> error(int code, String message) {
        return new BaseResponse<>(code, message, null);
    }

    /**
     * 失败，错误码
     * @param errorCode 自定义错误码
     * @param <T> null
     * @return 通用响应类
     */
    public static <T> BaseResponse<T> error(ErrorCode errorCode) {
        return new BaseResponse<>(errorCode);
    }

    /**
     * 失败，错误码，错误信息
     * @param errorCode 错误码
     * @param message 错误信息
     * @param <T> null
     * @return 统一响应类
     */
    public static <T> BaseResponse<T> error(ErrorCode errorCode, String message) {
        return new BaseResponse<>(errorCode.getCode(), message, null);
    }
}
