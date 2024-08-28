package com.hanshan.hanshanusercenterbackend.easyexcel;

import com.alibaba.excel.annotation.ExcelProperty;
import lombok.Data;

@Data
public class YuShanHanUserInfo {

    @ExcelProperty("id")
    private Long id;

    @ExcelProperty("昵称")
    private String nickname;
}
