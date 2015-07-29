# nginx-http-oauth-module

This module can be used for api checking, is similar like oauth 2 legged authentication.

## 1. Install Handlersocket

https://github.com/DeNA/HandlerSocket-Plugin-for-MySQL

https://github.com/DeNA/HandlerSocket-Plugin-for-MySQL/blob/master/docs-en/installation.en.txt


## 2. Create Table 

CREATE TABLE `oauth_access_token` (

  `id` int(10) NOT NULL AUTO_INCREMENT,

  `access_token` varchar(255) DEFAULT NULL,

  `expires_in` int(10) NOT NULL,

  `last_used_time` int(10) NOT NULL,

  PRIMARY KEY (`id`),

  KEY `ACCESS_TOKEN` (`access_token`)

) ENGINE=InnoDB DEFAULT CHARSET=utf8;


## 3. Install Oauth Module

> cd /work/nginx-1.8.0 && ./configure --add-module=/work/nginx-http-oauth-module && make


## 4. Add Config

see nginx.conf please


## 5. Using Oauth Module

a) generate access token

http://192.168.1.104/token?appid=some_appid&secret=some_secret

b) check access token

http://192.168.1.104/api/test.php?access_token=some_access_token
