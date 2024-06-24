package com.hanshan.hanshanusercenterbackend;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com/hanshan/hanshanusercenterbackend/mapper")
public class HanshanUserCenterBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(HanshanUserCenterBackendApplication.class, args);
    }

}
