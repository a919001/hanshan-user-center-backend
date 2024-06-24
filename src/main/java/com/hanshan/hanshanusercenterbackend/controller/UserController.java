package com.hanshan.hanshanusercenterbackend.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.hanshan.hanshanusercenterbackend.common.BaseResponse;
import com.hanshan.hanshanusercenterbackend.common.ErrorCode;
import com.hanshan.hanshanusercenterbackend.common.ResultUtils;
import com.hanshan.hanshanusercenterbackend.constant.UserConstant;
import com.hanshan.hanshanusercenterbackend.model.domain.User;
import com.hanshan.hanshanusercenterbackend.model.request.UserPasswordLoginRequest;
import com.hanshan.hanshanusercenterbackend.model.request.UserRegisterRequest;
import com.hanshan.hanshanusercenterbackend.service.UserService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin
@RestController
@RequestMapping("/user")
public class UserController {

    @Resource
    private UserService userService;

    @PostMapping("/register")
    public BaseResponse<Long> userRegister(@RequestBody UserRegisterRequest userRegisterRequest,
                                           HttpServletRequest request) {
        return userService.userRegister(userRegisterRequest, request);
    }

    @GetMapping("/verify-code")
    public void getVerifyCode(HttpServletRequest request) {
        userService.getVerifyCode(request);
    }

    @PostMapping("/passwordLogin")
    public BaseResponse<User> userPasswordLogin(@RequestBody UserPasswordLoginRequest userPasswordLoginRequest,
                                                HttpServletRequest request) {
        return userService.userPasswordLogin(userPasswordLoginRequest, request);
    }

    @PostMapping("/logout")
    public BaseResponse<String> userLogout(HttpServletRequest request) {
        return userService.userLogout(request);
    }

    @GetMapping("/current")
    public BaseResponse<User> getCurrentUser(HttpServletRequest request) {
        User currentUser = (User) request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        if (currentUser == null) {
            return ResultUtils.error(ErrorCode.NOT_LOGIN_ERROR, "请先登录");
        }
        Long currentUserId = currentUser.getId();
        User user = userService.getById(currentUserId);
        // todo 校验用户是否合法
        User safetyUser = userService.getSafetyUser(user);
        return ResultUtils.success(safetyUser);
    }

    @GetMapping("/search")
    public BaseResponse<List<User>> searchUsers(String username, HttpServletRequest request) {
        // 鉴权
        if (!isAdmin(request)) {
            return ResultUtils.error(ErrorCode.NO_AUTH_ERROR);
        }
        // 查询
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        if (StrUtil.isNotBlank(username)) {
            userQueryWrapper.like("username", username);
        }
        List<User> userList = userService.list(userQueryWrapper);
        // 用户脱敏
        List<User> users = userList.stream().map(user -> userService.getSafetyUser(user)).collect(Collectors.toList());
        return ResultUtils.success(users);
    }

    @PostMapping("/delete")
    public BaseResponse<Boolean> deleteUser(@RequestBody Long id, HttpServletRequest request) {
        if (isAdmin(request)) {
            if (id < 0) {
                return ResultUtils.error(ErrorCode.PARAMS_ERROR);
            }
            return ResultUtils.success(userService.removeById(id));
        } else {
            return ResultUtils.error(ErrorCode.NO_AUTH_ERROR);
        }
    }

    /**
     * 鉴权
     * @param request 获取登录态
     * @return 是否为管理员
     */
    private boolean isAdmin(HttpServletRequest request) {
        User user = (User) request.getSession().getAttribute(UserConstant.USER_LOGIN_STATE);
        return user != null && user.getUserRole() == UserConstant.ADMIN_ROLE;
    }
}
