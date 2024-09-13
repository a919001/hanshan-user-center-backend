package com.hanshan.hanshanusercenterbackend.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.hanshan.hanshanusercenterbackend.common.BaseResponse;
import com.hanshan.hanshanusercenterbackend.common.ErrorCode;
import com.hanshan.hanshanusercenterbackend.common.ResultUtils;
import com.hanshan.hanshanusercenterbackend.exception.BusinessException;
import com.hanshan.hanshanusercenterbackend.model.domain.User;
import com.hanshan.hanshanusercenterbackend.model.request.*;
import com.hanshan.hanshanusercenterbackend.service.UserService;
import org.springframework.util.CollectionUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

import static com.hanshan.hanshanusercenterbackend.constant.UserConstant.USER_LOGIN_STATE;
import static com.hanshan.hanshanusercenterbackend.utils.OssAdd.upload;

@CrossOrigin(origins = {"http://localhost:5173/"}, allowCredentials = "true")
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
    public BaseResponse<String> getVerifyCode(@RequestParam(value = "phone") String phone, HttpServletRequest request) throws Exception {
        userService.getVerifyCode(phone, request);
        return ResultUtils.success("验证码获取成功");
    }

    @PostMapping("/passwordLogin")
    public BaseResponse<User> userPasswordLogin(@RequestBody UserPasswordLoginRequest userPasswordLoginRequest,
                                                HttpServletRequest request) {
        return userService.userPasswordLogin(userPasswordLoginRequest, request);
    }

    @PostMapping("/phoneLogin")
    public BaseResponse<User> userPhoneLogin(@RequestBody UserPhoneLoginRequest userPhoneLoginRequest,
                                             HttpServletRequest request) {
        return userService.userPhoneLogin(userPhoneLoginRequest, request);
    }

    @PostMapping("/logout")
    public BaseResponse<String> userLogout(HttpServletRequest request) {
        return userService.userLogout(request);
    }

    @GetMapping("/current")
    public BaseResponse<User> getCurrentUser(HttpServletRequest request) {
        User currentUser = (User) request.getSession().getAttribute(USER_LOGIN_STATE);
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
        if (!userService.isAdmin(request)) {
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

    /**
     * 根据标签搜索用户
     *
     * @param tagNameList 标签列表
     * @return 用户结果集
     */
    @GetMapping("/search/tags")
    public BaseResponse<List<User>> searchUserByTags(@RequestParam(required = false) List<String> tagNameList) {
        if (CollectionUtils.isEmpty(tagNameList)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        List<User> userList = userService.searchUserByTags(tagNameList);
        return ResultUtils.success(userList);
    }

    @GetMapping("/recommend")
    public BaseResponse<List<User>> recommendUsers(long pageNum, long pageSize) {
        // 查询
        QueryWrapper<User> userQueryWrapper = new QueryWrapper<>();
        Page<User> page = userService.page(new Page<>(pageNum, pageSize), userQueryWrapper);
        // 用户脱敏
        List<User> users = page.getRecords().stream().map(user -> userService.getSafetyUser(user)).collect(Collectors.toList());
        return ResultUtils.success(users);
    }
    @PostMapping("/delete")
    public BaseResponse<Boolean> deleteUser(@RequestBody UserDeleteRequest userDeleteRequest, HttpServletRequest request) {
        Long id = userDeleteRequest.getId();
        if (userService.isAdmin(request)) {
            if (id < 0) {
                return ResultUtils.error(ErrorCode.PARAMS_ERROR);
            }
            return ResultUtils.success(userService.removeById(id));
        } else {
            return ResultUtils.error(ErrorCode.NO_AUTH_ERROR);
        }
    }

    @PostMapping("/upload")
    public BaseResponse<String> uploadAvatar(@RequestParam("avatar") MultipartFile file, HttpServletRequest request) {
        String avatarUrl = upload(file);
        User user = (User) request.getSession().getAttribute(USER_LOGIN_STATE);
        UpdateWrapper<User> userUpdateWrapper = new UpdateWrapper<>();
        userUpdateWrapper.eq("id", user.getId()).set("avatar", avatarUrl);
        if (!userService.update(userUpdateWrapper)) {
            return ResultUtils.error(ErrorCode.OPERATION_ERROR, "更新头像失败");
        }
        return ResultUtils.success(avatarUrl);
    }

    @PostMapping("/update-personal-info")
    public BaseResponse<User> updatePersonalInfo(@RequestBody UserUpdateInfoRequest userUpdateInfoRequest,
                                                 HttpServletRequest request) {
        return userService.updatePersonalInfo(userUpdateInfoRequest, request);
    }

    @PostMapping("update")
    public BaseResponse<Integer> updateUser(@RequestBody User user, HttpServletRequest request) {
        // 验证参数是否为空
        if (user == null) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        // 鉴权
        User loginUser = userService.getLoginUser(request);
        int result = userService.updateUser(user, loginUser);
        return ResultUtils.success(result);
    }
}
