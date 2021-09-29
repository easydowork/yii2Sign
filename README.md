### https://www.yiichina.com 自动签到

- php 版本大于7.0小于7.4
- 打开`sign.php`配置UserName PassWord

- php cli 模式下 运行：
```sh
php sign.php
```

- 凌晨12点定时任务运行：
```sh
59 23 * * *  /path/php sign.php crontab > /path/sign.log
```