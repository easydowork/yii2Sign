<?php
//php下载m3u8文件

define('M3U8_URL','https://cn2.zuidadianying.com/ppvod/616B8351DA081A079D35C0936482E1BA.m3u8');
define('TS_URL','https://cn2.zuidadianying.com/20190306/6wweKAmz/800kb/hls/');
define('MOVE_NAME','假若比尔街能说话');

if(!file_exists('./tmp/')) {
    if(!mkdir('./tmp/')) {
        exit('请手动在当前目录创建tmp目录');
    }
}

$indexPage = file_get_contents(M3U8_URL);

preg_match_all('/.*\.ts/', $indexPage, $matches);
if(empty($matches)) {
    die('m3u8 文件格式错误');
}

go(function() use($matches) {
    $chan = new chan(100); //最大并发数
    foreach($matches['0'] as $key => $value) {
        if(file_exists('./tmp/'.$key.'.ts')) {
            continue;
        }
        $chan->push('xx');
        go(function() use($key, $value, $chan) {
            echo "\nAdd task:".$key;
            while(1) {
                $rs = co_curl(TS_URL.$value);
                if(strlen($rs) > 0) {
                    file_put_contents('./tmp/'.$key.'.ts', $rs);
                    break;
                }
            }
            echo "\nTask ok:".$key;
            $chan->pop();
        });
    }
    //确保所有下载已经完成
    for($i = 0; $i < 100; $i++) {
        $chan->push('over');
    }
    //合并文件
    foreach ($matches['0'] as $key => $value) {
        file_put_contents(MOVE_NAME.'.mp4', file_get_contents('./tmp/'.$key.'.ts'), FILE_APPEND);
        unlink('./tmp/'.$key.'.ts');
    }
    echo "\n 下载完成，转换成功 (out.mp4)";
});

function co_curl($url, $cookies = '', $data = array(), $userHeaders = array(), $retJson = 0)
{
    while(1) {
        $urlInfo  = parse_url($url);
        $domain   = $urlInfo['host'];
        if($urlInfo['scheme'] == 'https') {
            $port = 443;
            $ssl = true;
        } else {
            $port = isset($urlInfo['port']) ? $urlInfo['port'] : 80;
            $ssl = false;
        }
        $filename = $urlInfo['path'];
        $filename .= isset($urlInfo['query']) ? '?' . $urlInfo['query'] : '';

        $cli     = new Swoole\Coroutine\Http\Client($domain, $port, $ssl);
        $headers = [
            'Host'            => $domain,
            "User-Agent"      => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36',
            'Accept'          => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ];
        if ($userHeaders) {
            $headers = array_merge($headers, $userHeaders);
            $headers = $userHeaders;
        }
        if ($cookies) {
            $headers['Cookie'] = $cookies;
        }
        $cli->setHeaders($headers);
        $cli->set(['timeout' => 60]);
        if ($data) {
            if($data == 'post') {
                $data = '';
            }
            $cli->post($filename, $data);
        } else {
            $cli->get($filename);
        }

        $body = $cli->body;
        $cli->close();

        if($cli->statusCode < 1 || ($retJson  && empty(json_decode($body, true)))) {
            // echo "\n status code:" . $cli->statusCode;
            // echo "\n body: ".$body;
            // echo "\n retry...";
        } else {
            return $body;
        }
    }
}