<?php
define('SITE_URL','https://www.asas.com/');
define('SITE_HOST','www.asas.com');

require_once __DIR__ . '/vendor/autoload.php';
use Curl\Curl;

class SaveImg
{

    /**
     * @var Curl
     */
    private $curl;

    /**
     * @var array
     */
    private $urlList;

    public function __construct()
    {
        $this->curl = new Curl();
        //设置  UA
        $this->curl->setUserAgent('Mozilla/5.0 (X11; Linux x86_64…) Gecko/20100101 Firefox/60.0');
        //带上 请求 头
        $this->curl->setHeader('X-Requested-With', 'XMLHttpRequest');
    }

    /**
     * checkUrl
     * @param $url
     * @return bool
     */
    public function checkUrl($url)
    {
        $host = parse_url($url)['host']??'';
        return $host==SITE_HOST?true:false;
    }

    /**
     * getContentByUrl
     * @param $url
     */
    public function getContentByUrl($url)
    {
        $this->urlList[md5($url)] = $url;
        //请求页面
        $this->curl->get($url);
        //解析页面
        $doc = phpQuery::newDocumentHTML($this->curl->response);
        $this->getImgByContent($doc);
        $this->getALinkByContent($doc);
    }

    /**
     * getALinkByContent
     * @param $doc phpQueryObject
     */
    public function getALinkByContent($doc)
    {
        $aEle = $doc->find('a');
        for ($i=0;$i<count($aEle);$i++){
            $href = $aEle->eq($i)->attr('href');
            echo "获取链接 {$href} 成功.".PHP_EOL;
            if(!isset($this->urlList[md5($href)])){
                if(!$this->checkUrl($href)){
                    echo "链接 {$href} 不在范围内.".PHP_EOL;
                    continue;
                }
                $this->getContentByUrl($href);
            }
        }
    }

    /**
     * getImgByContent
     * @param $doc phpQueryObject
     */
    public function getImgByContent($doc)
    {
        $imgEle = $doc->find('img');
        for ($i=0;$i<count($imgEle);$i++){
            $this->saveImgByLink($imgEle->eq($i)->attr('src'));
        }
    }

    /**
     * saveImgByLink
     * @param $link
     */
    public function saveImgByLink($link)
    {
        $fileName = md5($link).'.jpg';
        $path = __DIR__.'/535zh/';
        $file = $path.$fileName;
        if(!is_file($file)){
            file_put_contents($file,file_get_contents($link));
            echo "保存图片 {$link} 成功.".PHP_EOL;
        }
    }
}

$obj = new SaveImg();
$obj->getContentByUrl(SITE_URL);
