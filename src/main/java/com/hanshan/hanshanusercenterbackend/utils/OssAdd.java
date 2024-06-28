package com.hanshan.hanshanusercenterbackend.utils;

import com.aliyun.oss.ClientException;
import com.aliyun.oss.OSS;
import com.aliyun.oss.OSSClientBuilder;
import com.aliyun.oss.OSSException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

public class OssAdd {
    /**
     * 上传到OSS // todo 当前使用临时访问实现，后续需优化
     * @param file 目标文件
     * @return OSS 存储地址
     */
    public static String upload(MultipartFile file) {
        // OSS Region
        String endpoint = "https://oss-cn-beijing.aliyuncs.com";

        String accessKeyId = "LTAI5t8Gk33ovkwSwtxaX85V";
        String accessKeySecret = "4wKXQUF1bvIGehs5Qy0NA29iPFWngt";
        // Bucket名称
        String bucketName = "yu-shan-han";
        // 文件名拼接
        String prefix = "user-center/avatar";
        String datePath = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String path = prefix + "-" + datePath + "-" + uuid + file.getOriginalFilename();

        // 创建OSSClient实例。
        OSS ossClient = new OSSClientBuilder().build(endpoint, accessKeyId, accessKeySecret);

        try {
            ossClient.putObject(bucketName, path, file.getInputStream());
        } catch (OSSException oe) {
            System.out.println("Caught an OSSException, which means your request made it to OSS, "
                    + "but was rejected with an error response for some reason.");
            System.out.println("Error Message:" + oe.getErrorMessage());
            System.out.println("Error Code:" + oe.getErrorCode());
            System.out.println("Request ID:" + oe.getRequestId());
            System.out.println("Host ID:" + oe.getHostId());
        } catch (ClientException ce) {
            System.out.println("Caught an ClientException, which means the client encountered "
                    + "a serious internal problem while trying to communicate with OSS, "
                    + "such as not being able to access the network.");
            System.out.println("Error Message:" + ce.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (ossClient != null) {
                ossClient.shutdown();
            }
        }

        return "https://" + bucketName + ".oss-cn-beijing.aliyuncs.com/" + path;
    }
}
