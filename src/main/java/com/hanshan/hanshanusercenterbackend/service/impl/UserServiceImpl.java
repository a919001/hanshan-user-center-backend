package com.hanshan.hanshanusercenterbackend.service.impl;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.DesensitizedUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hanshan.hanshanusercenterbackend.common.BaseResponse;
import com.hanshan.hanshanusercenterbackend.common.ErrorCode;
import com.hanshan.hanshanusercenterbackend.common.ResultUtils;
import com.hanshan.hanshanusercenterbackend.common.VerifyCodeHolder;
import com.hanshan.hanshanusercenterbackend.constant.UserConstant;
import com.hanshan.hanshanusercenterbackend.mapper.UserMapper;
import com.hanshan.hanshanusercenterbackend.model.domain.User;
import com.hanshan.hanshanusercenterbackend.model.request.UserPasswordLoginRequest;
import com.hanshan.hanshanusercenterbackend.model.request.UserPhoneLoginRequest;
import com.hanshan.hanshanusercenterbackend.model.request.UserRegisterRequest;
import com.hanshan.hanshanusercenterbackend.model.request.UserUpdateInfoRequest;
import com.hanshan.hanshanusercenterbackend.service.UserService;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static com.hanshan.hanshanusercenterbackend.constant.UserConstant.*;
import static com.hanshan.hanshanusercenterbackend.utils.SendSms.sendSms;

/**
 * @author 寒山
 * @description 针对表【user(用户表)】的数据库操作Service实现
 * @createDate 2024-06-18 09:07:51
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
        implements UserService {

    @Resource
    private UserMapper userMapper;

    @Override
    public BaseResponse<Long> userRegister(UserRegisterRequest userRegisterRequest, HttpServletRequest request) {
        // 用户名
        String username = userRegisterRequest.getUsername();
        // 密码
        String password = userRegisterRequest.getPassword();
        // 校验密码
        String checkPassword = userRegisterRequest.getCheckPassword();
        // 手机号
        String phone = userRegisterRequest.getPhone();
        // 校验码
        String verifyCode = userRegisterRequest.getVerifyCode();
        // 对所有属性判空
        if (StrUtil.hasBlank(username, password, checkPassword, phone, verifyCode)) {
            return ResultUtils.error(ErrorCode.PARAMS_NULL_ERROR);
        }
        if (username.length() < 6 || username.length() > 32) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "用户名长度错误");
        }
        // 用户名不能包含特殊字符
        String validPattern = "^[a-zA-Z0-9_-]{6,16}$";
        if (!username.matches(validPattern)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "用户名不能包含特殊字符");
        }
        if (password.length() < 6 || password.length() > 32) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "密码长度错误");
        }
        if (!password.equals(checkPassword)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "两次密码不一致");
        }
        // 校验手机号格式
        if (!phone.matches("^(13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\\d{8}$")) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "手机号格式错误");
        }
        // 用户名是否重复
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        userQueryWrapper.eq("username", username);
        Long count = userMapper.selectCount(userQueryWrapper);
        if (count != null && count > 0) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "该用户名已存在");
        }
        // 手机号是否重复
        userQueryWrapper.clear();
        userQueryWrapper.eq("phone", phone);
        Long phoneCount = userMapper.selectCount(userQueryWrapper);
        if (phoneCount != null && phoneCount > 0) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "该手机号已被注册");
        }
        // 密码加密
        String encryptPassword = SecureUtil.md5(password);
        // 手机号加密
        String encryptPhone = SecureUtil.aes(UserConstant.AES_KEY.getBytes(StandardCharsets.UTF_8)).encryptBase64(phone, "UTF-8");
        // 取出校验码
        VerifyCodeHolder storedVerifyCodeHolder = (VerifyCodeHolder) request.getSession().getAttribute(VERIFY_CODE);
        // 是否过期
        if (verifyCodeWhetherExpired(storedVerifyCodeHolder)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "验证码已过期");
        }
        String checkCode = storedVerifyCodeHolder.getCode();
        // 校验验证码
        if (!verifyCode.equals(checkCode)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "验证码错误，请重试");
        }
        // 销毁验证码
        request.getSession().removeAttribute("verifyCode");
        // 封装对象
        User user = new User();
        user.setUsername(username);
        user.setPassword(encryptPassword);
        // 默认设置昵称为用户名
        user.setNickname(username);
        user.setPhone(encryptPhone);
        // 插入数据
        int res = userMapper.insert(user);
        if (res != 1) {
            return ResultUtils.error(ErrorCode.OPERATION_ERROR, "服务异常，注册用户失败");
        }
        return ResultUtils.success(user.getId());
    }

    @Override
    public void getVerifyCode(String phone, HttpServletRequest request) throws Exception {
        String verifyCode = RandomUtil.randomNumbers(6);
        System.out.println("verifyCode = " + verifyCode);
        sendSms(phone, verifyCode);
        VerifyCodeHolder verifyCodeHolder = new VerifyCodeHolder(verifyCode);
        request.getSession().setAttribute(VERIFY_CODE, verifyCodeHolder);
    }

    @Override
    public BaseResponse<User> userPasswordLogin(UserPasswordLoginRequest userPasswordLoginRequest, HttpServletRequest request) {
        String username = userPasswordLoginRequest.getUsername();
        String password = userPasswordLoginRequest.getPassword();
        if (StrUtil.hasBlank(username, password)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "请求参数不合法");
        }
        // 用户名不能包含特殊字符
        String validPattern = "^[a-zA-Z0-9_-]{6,16}$";
        if (!username.matches(validPattern)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "用户名不能包含特殊字符");
        }
        if (username.length() < 6 || username.length() > 32) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "用户名长度错误");
        }
        if (password.length() < 6 || password.length() > 32) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "密码长度错误");
        }
        // 查找用户
        QueryWrapper<User> qw = new QueryWrapper<>();
        qw.eq("username", username);
        User user = userMapper.selectOne(qw);
        // 用户不存在
        if (user == null) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "用户名或密码错误");
        }
        // 比对密码
        String encryptPassword = SecureUtil.md5(password);
        if (!encryptPassword.equals(user.getPassword())) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "用户名或密码错误");
        }
        // 得到脱敏后的用户
        User safetyUser = getSafetyUser(user);
        // 记录用户登录态
        request.getSession().setAttribute(USER_LOGIN_STATE, safetyUser);
        return ResultUtils.success(safetyUser);
    }

    @Override
    public User getSafetyUser(User user) {
        if (user == null) {
            return null;
        }
        // 用户脱敏
        User safetyUser = new User();
        safetyUser.setId(user.getId());
        safetyUser.setUsername(user.getUsername());
        safetyUser.setAvatar(user.getAvatar());
        safetyUser.setNickname(user.getNickname());
        safetyUser.setGender(user.getGender());
        safetyUser.setBirthday(user.getBirthday());
        safetyUser.setRegion(user.getRegion());
        safetyUser.setSignature(user.getSignature());
        // 解密手机号并脱敏
        String phone = SecureUtil.aes(UserConstant.AES_KEY.getBytes(StandardCharsets.UTF_8))
                .decryptStr(user.getPhone(), StandardCharsets.UTF_8);
        safetyUser.setPhone(DesensitizedUtil.mobilePhone(phone));
        // 邮箱脱敏
        safetyUser.setEmail(DesensitizedUtil.email(user.getEmail()));
        safetyUser.setUserStatus(user.getUserStatus());
        safetyUser.setUserRole(user.getUserRole());
        safetyUser.setCreateTime(user.getCreateTime());
        safetyUser.setUpdateTime(user.getUpdateTime());
        return safetyUser;
    }

    @Override
    public BaseResponse<String> userLogout(HttpServletRequest request) {
        if (request == null) {
            return ResultUtils.error(ErrorCode.OPERATION_ERROR, "session 错误");
        }
        request.getSession().removeAttribute(USER_LOGIN_STATE);
        return ResultUtils.success("退出成功");
    }

    @Override
    public BaseResponse<User> updatePersonalInfo(UserUpdateInfoRequest userUpdateInfoRequest, HttpServletRequest request) {

        // 1. 获取用户登录态
        User currentUser = (User) request.getSession().getAttribute(USER_LOGIN_STATE);
        // 2. 设置更新信息
        UpdateWrapper<User> updateWrapper = new UpdateWrapper<>();
        updateWrapper.eq("id", currentUser.getId());
        User updateUser = new User();
        BeanUtil.copyProperties(userUpdateInfoRequest, updateUser);
        // 3. 执行更新操作
        int rows = userMapper.update(updateUser, updateWrapper);
        if (rows <= 0) {
            return ResultUtils.error(ErrorCode.OPERATION_ERROR, "更新数据时错误");
        }
        // 4. 查询更新后的用户信息
        User user = userMapper.selectById(currentUser.getId());
        // 6. 返回更新后的脱敏用户信息
        User safetyUser = getSafetyUser(user);
        return ResultUtils.success(safetyUser);
    }

    @Override
    public BaseResponse<User> userPhoneLogin(UserPhoneLoginRequest userPhoneLoginRequest, HttpServletRequest request) {
        String phone = userPhoneLoginRequest.getPhone();
        String code = userPhoneLoginRequest.getVerifyCode();
        // 对属性判空
        if (StrUtil.hasBlank(phone, code)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "参数不能为空");
        }
        // 根据加密后的手机号进行用户查询
        String encryptPhone = SecureUtil.aes(UserConstant.AES_KEY.getBytes(StandardCharsets.UTF_8))
                .encryptBase64(phone, "UTF-8");
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        userQueryWrapper.eq("phone", encryptPhone);
        User user = userMapper.selectOne(userQueryWrapper);
        if (user == null) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "该用户不存在");
        }
        VerifyCodeHolder storedVerifyCodeHolder = (VerifyCodeHolder) request.getSession().getAttribute("verifyCode");
        if (verifyCodeWhetherExpired(storedVerifyCodeHolder)) {
            // 销毁验证码
            request.getSession().removeAttribute(VERIFY_CODE);
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "验证码已过期");
        }
        String verifyCode = storedVerifyCodeHolder.getCode();
        if (!code.equals(verifyCode)) {
            return ResultUtils.error(ErrorCode.PARAMS_ERROR, "验证码错误");
        }
        User safetyUser = getSafetyUser(user);
        // 记录用户登录态
        request.getSession().setAttribute(USER_LOGIN_STATE, safetyUser);
        return ResultUtils.success(safetyUser);
    }

    /**
     * 判断验证码是否过期
     * @return true 已过期，false 未过期
     */
    private boolean verifyCodeWhetherExpired(VerifyCodeHolder storedVerifyCodeHolder) {
        if (storedVerifyCodeHolder == null) {
            return true;
        }
        return new Date().getTime() - storedVerifyCodeHolder.getGenerationTime().getTime() >= VERIFY_CODE_EXPIRED_TIME;
    }
}


