package com.hanshan.hanshanusercenterbackend.easyexcel;

import cn.hutool.json.JSONUtil;
import com.alibaba.excel.EasyExcel;
import com.alibaba.excel.read.listener.PageReadListener;
import com.alibaba.excel.support.ExcelTypeEnum;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ImportExcel {

    public static void main(String[] args) {
        read();
    }

    public static void read() {
        // 写法1：JDK8+ ,不用额外写一个DataListener
        // since: 3.0.0-beta1
        String fileName = System.getProperty("user.dir") + "/src/main/resources/static/testExcel.xlsx";
        // 这里默认每次会读取100条数据 然后返回过来 直接调用使用数据就行
        // 具体需要返回多少行可以在`PageReadListener`的构造函数设置
        EasyExcel.read(fileName, YuShanHanUserInfo.class, new PageReadListener<YuShanHanUserInfo>(dataList -> {
            for (YuShanHanUserInfo YuShanHanUserInfo : dataList) {
                log.info("读取到一条数据{}", JSONUtil.toJsonStr(YuShanHanUserInfo));
            }
        })).excelType(ExcelTypeEnum.XLSX).sheet().doRead();

        // 写法2
        EasyExcel.read(fileName, YuShanHanUserInfo.class, new DataListener()).sheet().doRead();
    }
}
