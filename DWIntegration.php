<?php declare(strict_types=1);



$dwInfo = new DWIntegration("PASSPHRASE");
$dwInfo->setServer("https://SERVER.com");
$dwInfo->setDocId("DOCID");
$dwInfo->setUser("USER");
$dwInfo->setPassword("PASSWORD");
$dwInfo->setFileCabinet("FILECABINET");

echo $dwInfo->getURL();

class DWIntegration {
    private string $server;
    private string $docId;
    private string $passphrase;
    private string $user;
    private string $password;
    private string $fileCabinet;
    private string $url;
    private string $encryptionKey;
    private string $iv;
    private array $parameters = array();

    public function __construct($passphrase) {
        $this->cryptPassphrase($passphrase);
    }

    private function cryptPassphrase($passphrase) {
        $this->passphrase = hash('sha512', $passphrase, true);
        $this->encryptionKey  = substr($this->passphrase,0,32);
        $this->iv = substr($this->passphrase,32,16);
    }

    private function makeParameters() {
        $this->parameters = array(
            'p' => 'V',
            'did' => $this->getDocId(),
            'lc' => $this->generateEncodedLogin(),
            'fc' => $this->getFileCabinet()
        );

        $qs = implode("&", array_map(
                function ($v, $k) { return sprintf("%s=%s", $k, $v); },
                $this->parameters,
            array_keys($this->parameters)));
        return $this->convertToUrlTokenFormat(base64_encode(openssl_encrypt($qs, 'aes-256-cbc', $this->encryptionKey, OPENSSL_RAW_DATA, $this->iv)));
    }

    private function generateEncodedLogin() {
        $lc = 'User=' . $this->getUser() . '\nPwd=' . $this->getPassword();
        return $this->convertToUrlTokenFormat(base64_encode($lc));
    }

    private function convertToUrlTokenFormat($val) {
        $padding = substr_count($val, '=');
        $val = str_replace('=', '', $val);
        $val .= $padding;
        $val = str_replace('+', '-', str_replace('/', '_', $val));
        return $val;
    }

    /**
     * Get the value of server
     */ 
    public function getServer()
    {
        return $this->server;
    }

    /**
     * Set the value of server
     *
     * @return  self
     */ 
    public function setServer($server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Get the value of docId
     */ 
    public function getDocId()
    {
        return $this->docId;
    }

    /**
     * Set the value of docId
     *
     * @return  self
     */ 
    public function setDocId($docId)
    {
        $this->docId = $docId;

        return $this;
    }

    /**
     * Get the value of user
     */ 
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Set the value of user
     *
     * @return  self
     */ 
    public function setUser($user)
    {
        $this->user = $user;

        return $this;
    }

    /**
     * Get the value of password
     */ 
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Set the value of password
     *
     * @return  self
     */ 
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Get the value of fileCabinet
     */ 
    public function getFileCabinet()
    {
        return $this->fileCabinet;
    }

    /**
     * Set the value of fileCabinet
     *
     * @return  self
     */ 
    public function setFileCabinet($fileCabinet)
    {
        $this->fileCabinet = $fileCabinet;

        return $this;
    }

    public function getURL() {
        $this->url = $this->getServer() . "/DocuWare/Platform/WebClient/Integration";
        $this->url.= '?ep=' . $this->makeParameters();
        return $this->url;
    }
}