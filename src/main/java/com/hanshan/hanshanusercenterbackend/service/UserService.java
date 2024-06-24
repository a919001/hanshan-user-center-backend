package com.hanshan.hanshanusercenterbackend.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.hanshan.hanshanusercenterbackend.common.BaseResponse;
import com.hanshan.hanshanusercenterbackend.model.domain.User;
import com.hanshan.hanshanusercenterbackend.model.request.UserPasswordLoginRequest;
import com.hanshan.hanshanusercenterbackend.model.request.UserRegisterRequest;

import javax.servlet.http.HttpServletRequest;

/**
* @author 寒山
* @description 针对表【user(用户表)】的数据库操作Service
* @createDate 2024-06-18 09:07:51
*/
public interface UserService extends IService<User> {

    /**
     * 用户注册
     * @param userRegisterRequest 用户注册请求体
     * @return 新用户id
     */
    BaseResponse<Long> userRegister(UserRegisterRequest userRegisterRequest, HttpServletRequest request);

    /**
     * 获取验证码 todo 之后使用云服务优化
     * @param request 暂时用session实现
     */
    void getVerifyCode(HttpServletRequest request);

    /**
     * 用户名密码登录 todo 手机号登录
     * @param userPasswordLoginRequest 用户名密码登录请求体
     * @param request HttpServletRequest
     * @return 脱敏后的用户信息
     */
    BaseResponse<User> userPasswordLogin(UserPasswordLoginRequest userPasswordLoginRequest, HttpServletRequest request);

    /**
     * 用户脱敏
     * @param user 原始用户信息
     * @return 脱敏后的用户信息
     */
    User getSafetyUser(User user);

    /**
     * 退出登录
     * @param request session会话
     * @return 操作结果
     */
    BaseResponse<String> userLogout(HttpServletRequest request);
}
