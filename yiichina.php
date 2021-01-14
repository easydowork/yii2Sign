<?php
require_once __DIR__ . '/vendor/autoload.php';
use Curl\Curl;

define('SiteUrl','https://www.yiichina.com/');   //站点URL
define('LoginUrl',SiteUrl.'login');             //登录页面地址
define('SignInUrl',SiteUrl.'ajax/registration');     //请求签到地址

define('UserName','小叮当的肚兜');      //账号 自己配置
define('PassWord','小叮当的肚兜');      //密码 自己配置

$curl = new Curl();

//请求登录页面
$curl->get(LoginUrl);

if ($curl->error) {
    echo '请求登录页面->Error: ' . $curl->errorCode . ': ' . $curl->errorMessage . "\n"; exit;
}

$loginHtml  = $curl->response;

$cookie  = $curl->getResponseCookies();

//解析登录页面
$doc = phpQuery::newDocumentHTML($loginHtml);

//获取防止 跨站请求伪造 加密字符串
$_csrf = $doc->find('input[name=_csrf]')->val();

/******************************************开始登录********************************************/
//带上Referrer
$curl->setReferrer(SiteUrl);

//设置  UA
$curl->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36');

//带上 请求 头
$curl->setHeader('X-Requested-With', 'XMLHttpRequest');

//带上 sessionId 的 cookie
$curl->setCookies($cookie);

$userInfo = [
    '_csrf'  => $_csrf,
    'LoginForm[username]'  => UserName,
    'LoginForm[password]'  => PassWord,
    'LoginForm[rememberMe]'  => '1',
];

$curl->post(LoginUrl,$userInfo,1);

if ($curl->error) {
    echo '开始登录->Error: ' . $curl->errorCode . ': ' . $curl->errorMessage . "\n"; exit;
}

//获取 登录的时产生的 cookie
$cookie  += $curl->getResponseCookies();


/******************************************开始签到********************************************/
//带上Referrer
$curl->setReferrer(SiteUrl);

//设置  UA
$curl->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36');

//带上 请求 头
$curl->setHeader('X-Requested-With', 'XMLHttpRequest');

//带上 sessionId 的 cookie
$curl->setCookies($cookie);

//签到
$curl->post(SignInUrl,['_csrf'=>$_csrf]);

if ($curl->error) {
    echo '开始签到->Error: ' . $curl->errorCode . ': ' . $curl->errorMessage . "\n"; exit;
}

$signInResponse  = $curl->response;

//{"status":1,"message":"已连续1天"}

$responseArray = json_decode(json_encode($signInResponse),1);

if($responseArray['status']?:0){
    $msg = date('Y-m-d').' sgin in OK'.PHP_EOL;
}else{
    $msg = date('Y-m-d').' sgin in Fail:'.($responseArray['message']?:'').PHP_EOL;
}

echo $msg;

file_put_contents(__DIR__.'login.log',$msg,FILE_APPEND);


