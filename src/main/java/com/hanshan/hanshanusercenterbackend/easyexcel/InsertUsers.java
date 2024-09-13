package com.hanshan.hanshanusercenterbackend.easyexcel;

import com.hanshan.hanshanusercenterbackend.mapper.UserMapper;
import com.hanshan.hanshanusercenterbackend.model.domain.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;

import javax.annotation.Resource;

@Component
public class InsertUsers {

    @Resource
    private UserMapper userMapper;

    // @Scheduled(initialDelay = 5000, fixedDelay = Long.MAX_VALUE)
    public void doInsertUser() {
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        final int INSERT_NUM = 1000;
        for (int i = 0; i < INSERT_NUM; i++) {
            User user = new User();
            user.setUsername("shanhan");
            user.setPassword("123456");
            user.setAvatar("https://yu-shan-han.oss-cn-beijing.aliyuncs.com/user-center/avatar-20240703135719-abe1f992914c46d7bebede212f83f533mmexport1596556925757.jpg");
            user.setNickname("假寒山");
            user.setRegion("中国");
            user.setPhone("12345678901");
            user.setEmail("hanshan@qq.com");
            user.setTags("[]");
            userMapper.insert(user);
        }
        stopWatch.stop();
        System.out.println(stopWatch.getLastTaskTimeMillis());
    }
}
