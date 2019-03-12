<?php

require_once __DIR__ . '/vendor/autoload.php';

use Curl\Curl;

$curl = new Curl();

//设置  UA
$curl->setUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36');
$curl->setReferer('https://www.52pojie.cn/forum.php');
$curl->setHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8');
$curl->setHeader('Accept-Encoding', 'gzipc');
$curl->setHeader('Host', 'www.52pojie.cn');
$curl->setHeader('Cache-Control', 'no-cache');
$curl->setHeader('Connection', 'keep-alive');
$curl->setHeader('Pragma', 'no-cache');
$curl->setHeader('Upgrade-Insecure-Requests', '1');

$cookieString = file_get_contents(__DIR__.'/cookies.log');

$curl->setCookieString($cookieString);

// 开始签到
$signUrl = 'https://www.52pojie.cn/home.php?mod=task&do=draw&id=2';
$curl->get($signUrl);

$signUrl = 'https://www.52pojie.cn/home.php?mod=task&do=apply&id=2';
$curl->get($signUrl);