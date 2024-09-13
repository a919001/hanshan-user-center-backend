package com.hanshan.hanshanusercenterbackend;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@MapperScan("com.hanshan.hanshanusercenterbackend.mapper")
@EnableScheduling
public class HanShanUserCenterBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(HanShanUserCenterBackendApplication.class, args);
    }

}
