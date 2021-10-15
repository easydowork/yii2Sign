<?php
require_once __DIR__ . '/YiiChina.php';

define('SiteUrl','https://www.yiichina.com/');   //站点URL
define('LoginUrl',SiteUrl.'login');             //登录页面地址
define('SignInUrl',SiteUrl.'ajax/registration');     //请求签到地址
define('LOGFILE',__DIR__.'/sign.log');     //日志文件

define('UserName','小叮当的肚兜');      //账号 自己配置
define('PassWord','小叮当的肚兜');      //密码 自己配置

if($argv[1]??'' == 'crontab'){
    $todayTime = time();
    $tomorrowTime = strtotime(date('Y-m-d'))+86400;
    if($tomorrowTime - $todayTime > 60){
        exit('未到签到时间.');
    }else{
        while (time() < $tomorrowTime){
            echo date('Y-m-d H:i:s').'---awaiting'.PHP_EOL;
            sleep(1);
        }
        sign();
    }
}else{
    sign();
}

function sign()
{
    $yiichina = new yiichina();
    for($i=0;$i<3;$i++){
        if($yiichina->sign()){
            $msg = date('Y-m-d H:i:s').' sgin in OK';
            @file_put_contents(LOGFILE,$msg.PHP_EOL,FILE_APPEND);
            break;
        }
    }
}