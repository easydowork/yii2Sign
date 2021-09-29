<?php
require_once __DIR__ . '/vendor/autoload.php';
use Curl\Curl;

class YiiChina
{
    /**
     * @var Curl
     */
    protected $curl;

    /**
     * @var array
     */
    protected $cookie = [];

    /**
     * @var string
     */
    protected $csrf = '';

    public function __construct()
    {
        $this->curl = new Curl();
        $this->curl->setOpt(CURLOPT_SSL_VERIFYPEER,0);
        $this->curl->setOpt(CURLOPT_SSL_VERIFYHOST,0);
        //设置  UA
        $this->curl->setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36');
    }

    /**
     * getCsrfAndCookie
     * @throws Exception
     */
    protected function getCsrfAndCookie()
    {
        //请求登录页面
        $this->curl->get(LoginUrl);

        if ($this->curl->error) {
            throw new \Exception('请求登录页面->Error: ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage);
        }

        //登录成功获取cookie
        $this->cookie  = $this->curl->getResponseCookies();

        //解析登录页面
        $doc = phpQuery::newDocumentHTML($this->curl->response);

        //获取防止 跨站请求伪造 加密字符串
        $this->csrf = $doc->find('input[name=_csrf]')->val();

    }

    /**
     * login
     * @throws Exception
     */
    protected function login()
    {
        //带上Referrer
        $this->curl->setReferrer(SiteUrl);

        //带上 请求 头
        $this->curl->setHeader('X-Requested-With', 'XMLHttpRequest');

        //带上 sessionId 的 cookie
        $this->curl->setCookies($this->cookie);

        $userInfo = [
            '_csrf'  => $this->csrf,
            'LoginForm[username]'  => UserName,
            'LoginForm[password]'  => PassWord,
            'LoginForm[rememberMe]'  => '1',
        ];

        $this->curl->post(LoginUrl,$userInfo,1);

        if ($this->curl->error) {
            throw new \Exception('开始登录->Error: ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage);
        }

        //获取 登录的时产生的 cookie
        //$this->cookie = array_merge($this->cookie,$this->curl->getResponseCookies());
        $this->cookie += $this->curl->getResponseCookies();
    }

    /**
     * sign
     * @return bool
     */
    public function sign()
    {
        try {
            $this->getCsrfAndCookie();

            $this->login();

            //带上Referrer
            $this->curl->setReferrer(SiteUrl);

            $this->curl->setHeader('X-Requested-With', 'XMLHttpRequest');

            //带上 sessionId 的 cookie
            $this->curl->setCookies($this->cookie);

            //签到
            $this->curl->post(SignInUrl,['_csrf'=>$this->csrf]);

            if ($this->curl->error) {
                throw new \Exception('开始签到->Error: ' . $this->curl->errorCode . ': ' . $this->curl->errorMessage);
            }

            $signInResponse  = $this->curl->response;

            //{"status":1,"message":"已连续1天"}

            $responseArray = json_decode(json_encode($signInResponse),1);

            if(($responseArray['status']??0) == 1){
                return true;
            }else{
                throw new \Exception($responseArray['message']?:'签到失败.');
            }
        }catch (\Exception $e){
            @file_put_contents(LOGFILE,date('Y-m-d H:i:s').'---'.$e->getMessage().PHP_EOL,FILE_APPEND);
            return false;
        }
    }

}


