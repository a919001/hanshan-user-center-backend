drop table if exists user;

create table user
(
    id          bigint primary key auto_increment comment '用户id',
    username    varchar(32)            not null comment '用户名',
    password    varchar(64)            not null comment '密码',
    avatar      varchar(255) comment '头像',
    nickname    varchar(32) comment '昵称',
    gender      tinyint comment '性别',
    birthday    date comment '生日',
    region      varchar(255) comment '地区',
    signature   varchar(511) default '这个人很懒，什么都没有留下。' comment '个性签名',
    phone       varchar(64) comment '手机',
    email       varchar(64) comment '邮箱',
    user_status int          default 0 comment '用户状态( 0 - 正常)',
    user_role   int          default 0 comment '用户角色（ 0 - 普通用户，1 - 管理员）',
    create_time datetime     default current_timestamp comment '创建时间',
    update_time datetime     default current_timestamp on update current_timestamp comment '更新时间',
    is_delete   tinyint      default 0 not null comment '逻辑删除（ 0 - 否，1 - 是）'
) comment '用户表';

