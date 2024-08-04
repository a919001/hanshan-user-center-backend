-- auto-generated definition
create table user
(
    id          bigint auto_increment comment '用户id'
        primary key,
    username    varchar(32)                                       not null comment '用户名',
    password    varchar(64)                                       not null comment '密码',
    avatar      varchar(255)                                      null comment '头像',
    nickname    varchar(32)                                       null comment '昵称',
    gender      tinyint                                           null comment '性别',
    birthday    date                                              null comment '生日',
    region      varchar(255)                                      null comment '地区',
    signature   varchar(511) default '这个人很懒，什么都没有留下。' null comment '个性签名',
    phone       varchar(64)                                       null comment '手机',
    email       varchar(64)                                       null comment '邮箱',
    user_status int          default 0                            null comment '用户状态( 0 - 正常 )',
    user_role   int          default 0                            null comment '用户角色( 0 - 普通用户，1 - 管理员 )',
    create_time datetime     default CURRENT_TIMESTAMP            null comment '创建时间',
    update_time datetime     default CURRENT_TIMESTAMP            null on update CURRENT_TIMESTAMP comment '更新时间',
    is_delete   tinyint      default 0                            not null comment '逻辑删除( 0 - 否，1 - 是 )',
    tags        varchar(1024)                                     null comment '标签列表( JSON )',
    constraint phone
        unique (phone)
)
    comment '用户表';



-- auto-generated definition
create table tag
(
    id          bigint auto_increment comment 'id'
        primary key,
    tag_name     varchar(256)                       not null comment '标签名',
    user_id      bigint                             not null comment '用户id',
    parent_d    bigint                             null comment '父标签id',
    is_parent    tinyint                            null comment '是否为父标签( 0 - 否, 1 - 是 )',
    create_time datetime default CURRENT_TIMESTAMP null comment '创建时间',
    update_time datetime default CURRENT_TIMESTAMP null on update CURRENT_TIMESTAMP comment '更新时间',
    is_delete   tinyint  default 0                 not null comment '逻辑删除( 0 - 否,1 - 是 )',
    constraint uniIdx_tagName
        unique (tag_name)
)
    comment '标签表';

create index idx_userId
    on tag (user_id);

