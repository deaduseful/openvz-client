<?php

/**
 * SSH class.
 *
 * @copyright Phurix 2009-2016.
 * @note: "PasswordAuthentication yes" must be set in the servers sshd_config
 *
 * Prerequisites:
 * yum install libssh2-devel
 * pear config-set preferred_state beta
 * pecl install ssh2
 * pear config-set preferred_state stable
 *
 * Example:
 * $ssh = new ssh();
 * $ssh->connect('host');
 * $ssh->auth('user', 'password');
 * $ssh->shellExecute('ps auxfc; ls');
 * $ssh->disconnect();
 */
class SSH
{
    /**
     * @var int
     */
    private $connected;
    /**
     * @var null
     */
    private $session = null;
    /**
     * @var null
     */
    private $stream = null;
    /**
     * @var string
     */
    private $end = '__COMMAND_ENDED__';
    /**
     * @var int
     */
    private $timeout = 10;
    /**
     * @var array
     */
    private $methods = array();
    /**
     * @var
     */
    private $fingerprint;
    /**
     * @var
     */
    private $pub_key_file;
    /**
     * @var
     */
    private $private_key_file;
    /**
     * @var
     */
    private $response;
    /**
     * @var
     */
    private $result;

    /**
     * @param $response
     * @return bool
     */
    function setResponse($response) {
        if ($response) {
            $this->response = $response;
        }
        return true;
    }

    /**
     * @return mixed
     */
    function getResponse() {
        if ($this->response) {
            return $this->response;
        }
        return false;
    }

    /**
     * @param $result
     * @return bool
     */
    function setResult($result) {
        if ($result) {
            $this->result = $result;
        }
        return true;
    }

    /**
     * @return null|resource
     * @throws Exception
     */
    function session() {
        if (!is_resource($this->session)) {
            $type = gettype($this->session);
            throw new Exception(__FUNCTION__ . "() expects parameter 1 to be resource, $type given");
        }
        return $this->session;
    }

    /**
     * @param string $host
     * @param int $port
     * @return bool|resource
     * @throws Exception
     */
    function connect($host = 'localhost', $port = 22) {
        if (!extension_loaded('ssh2')) {
            throw new Exception('the ssh2 extension has not been loaded');
        }
        if ($this->isConnected()) {
            throw new Exception('there may already be an active connection');
        }
        $connect = ssh2_connect($host, $port, $this->methods);
        if (!$connect) {
            throw new Exception('unable to establish connection');
        }
        $this->session = $connect;
        $this->finger($connect);
        return $connect;
    }

    /**
     * @param bool $connect
     * @return string
     */
    function finger($connect = false) {
        if (!$connect) {
            $connect = $this->session();
        }
        $fingerprint = ssh2_fingerprint($connect, SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX);
        $this->fingerprint = $fingerprint;
        return $fingerprint;
    }

    /**
     * @param string $private_key
     * @param bool $pub_key
     * @return bool
     */
    function setKeyFiles($private_key = 'id_rsa', $pub_key = false) {
        if (!$pub_key) {
            $pub_key = $private_key . '.pub';
        }
        $this->private_key_file = $private_key;
        $this->pub_key_file = $pub_key;
        return true;
    }

    /**
     * @param string $user
     * @param string $pass
     * @param bool $connect
     * @return bool
     * @throws Exception
     */
    function auth($user = 'root', $pass = '', $connect = false) {
        if (!$connect) {
            $connect = $this->session();
        }
        if ($this->pub_key_file && $this->private_key_file) {
            if (!file_exists($this->pub_key_file) || !file_exists($this->private_key_file)) {
                throw new Exception('unable to find the key files');
            }
            $auth = ssh2_auth_pubkey_file($connect, $user, $this->pub_key_file, $this->private_key_file, $pass);
        } else {
            $auth = ssh2_auth_password($connect, $user, $pass);
        }
        if ($auth) {
            $this->setConnected(true);
            $this->setResponse('connected and logged in');
            return $auth;
        }
        throw new Exception('unable to authenticate');
    }

    /**
     * @return bool
     * @throws Exception
     */
    function disconnect() {
        if (!$this->isConnected()) {
            throw new Exception('no ssh connection');
        }
        $this->settimeout(1);
        $this->shellExecute('exit;');
        $this->session = null;
        $this->stream = null;
        $this->setConnected(false);
        $this->setResponse('ssh session closed');
        return true;
    }

    /**
     * @param $file
     * @param string $remoteDest
     * @return bool
     * @throws Exception
     */
    function fileSend($file, $remoteDest = './') {
        if (!$this->isConnected()) {
            throw new Exception('no ssh connection');
        }
        if ((file_exists($file)) && is_readable($file)) {
            $filename = basename($file);
            $remoteDest = trim($remoteDest, '/');
            $remoteFile = $remoteDest . '/' . $filename;
            $send = ssh2_scp_send($this->session, $file, $remoteFile, 0644);
            if ($send) {
                $this->setResponse('file sent to server');
                return true;
            }
            throw new Exception('error sending file to remote host');
        }
        throw new Exception('the local file does not exist or is not readable');
    }

    /**
     * @param $file
     * @param bool $localDest
     * @return bool
     * @throws Exception
     */
    function fileGet($file, $localDest = false) {
        if (!$this->isConnected()) {
            throw new Exception('no ssh connection');
        }
        $filename = basename($file);
        if (!$localDest) {
            $localDest = getcwd();
        }
        $path = realpath($localDest);
        if (@ssh2_scp_recv($this->session, $file, $path . '/' . $filename)) {
            $this->setResponse('file received from server');
            return true;
        }
        throw new Exception('unable to receive remote file, SCP may be disabled...');
    }

    /**
     * @param $cmd
     * @return bool
     * @throws Exception
     */
    function execute($cmd) {
        if (!$this->isConnected()) {
            throw new Exception('no ssh connection');
        }
        $end = $this->end;
        $_cmd = preg_replace('/;+$/', '', $cmd);
        $exec = $_cmd . '; echo "' . $end . '"';
        $stream = ssh2_exec($this->session, $exec);
        if (!$stream) {
            throw new Exception('unable to execute command');
        }
        $time_start = time();
        $data = '';
        stream_set_blocking($stream, true);
        while ($stream) {
            $data .= fread($stream, 4096);
            $pattern = "/$end\s/";
            if (preg_match($pattern, $data)) {
                fclose($stream);
                $response = $this->cleanup($data);
                $this->setResponse($response);
                return true;
            }
            $timeout = $this->timeout();
            if ((time() - $time_start) > $timeout) {
                fclose($stream);
                throw new Exception("the request sent took to long to process or the connection timed out at $timeout seconds");
            }
        }
        throw new Exception('there was an error processing your request');
    }

    /**
     * @param $cmd
     * @return bool|mixed
     * @throws Exception
     */
    function shellExecute($cmd) {
        if (!$this->isConnected()) {
            throw new Exception('no ssh connection');
        }
        if (!$this->stream) {
            $this->stream = ssh2_shell($this->session, 'vt102', null, 180, 124, SSH2_TERM_UNIT_CHARS);
            if (!$this->stream) {
                throw new Exception('unable to create a stream to shell');
            }
        }
        $data = '';
        $time_start = time();
        $end = $this->end;
        $string = $cmd . '; echo "' . $end . '"' . PHP_EOL;
        fwrite($this->stream, preg_replace('/;+$/', '', $string));
        while ($this->stream) {
            $buf = fread($this->stream, 4096);
            $data .= $buf;
            $this->setResult($data);
            if (preg_match('/' . $end . '\s/', $data)) {
                return $this->cleanup($data);
            }
            $timeout = $this->timeout();
            if ((time() - $time_start) > $timeout) {
                throw new Exception("the request sent took to long to process or the connection timed out at $timeout seconds");
            }
        }
        throw new Exception('there was an error processing your request');
    }

    /**
     * @param int $sec
     */
    function setTimeout($sec = 10) {
        $this->timeout = $sec;
    }

    /**
     * @return int
     */
    function timeout() {
        return $this->timeout;
    }

    /**
     * @param $input
     * @return mixed
     */
    function cleanup($input) {
        $end = $this->end;
        $string = '; echo "' . $end . '"';
        $str_replace = str_replace($string, '', $input);
        return str_replace($end, '', $str_replace);
    }

    /**
     * @return bool
     */
    function isConnected() {
        if (!$this->connected) {
            $response = 'no ssh connection';
            $this->setResponse($response);
        }
        return (bool)$this->connected;
    }

    /**
     * @param bool $connected
     */
    function setConnected($connected = true) {
        $this->connected = $connected;
    }

}

//EOF