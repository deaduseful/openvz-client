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
    private $connected = 0;
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
     * @return bool|null|resource
     */
    function session() {
        if (!is_resource($this->session)) {
            $type = gettype($this->session);
            user_error(__FUNCTION__ . "() expects parameter 1 to be resource, $type given");
            return false;
        }
        return $this->session;
    }

    /**
     * @param string $host
     * @param int $port
     * @return bool|resource
     */
    function connect($host = 'localhost', $port = 22) {
        if (!extension_loaded('ssh2')) {
            $this->setResponse('the ssh2 extension has not been loaded');
            return false;
        }
        if ($this->connected) {
            $this->setResponse('there may already be an active connection');
            return false;
        }
        $connect = ssh2_connect($host, $port, $this->methods);
        if (!$connect) {
            $response = 'unable to establish connection';
            $this->setResponse($response);
            return false;
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
     */
    function auth($user = 'root', $pass = '', $connect = false) {
        if (!$connect) {
            $connect = $this->session();
        }
        if ($this->pub_key_file && $this->private_key_file) {
            if (!file_exists($this->pub_key_file) || !file_exists($this->private_key_file)) {
                $this->setResponse('unable find key_files');
                return false;
            }
            $auth = ssh2_auth_pubkey_file($connect, $user, $this->pub_key_file, $this->private_key_file, $pass);
        } else {
            $auth = ssh2_auth_password($connect, $user, $pass);
        }
        if ($auth) {
            $this->connected = 1;
            $this->setResponse('connected and logged in');
            return $auth;
        }
        $this->setResponse('unable to authenticate');
        return false;
    }

    /**
     * @return bool
     */
    function disconnect() {
        if ($this->connected == 1) {
            $this->settimeout(1);
            $this->shellExecute('exit;');
            $this->session = null;
            $this->stream = null;
            $this->connected = 0;
            $this->setResponse('ssh session closed');
            return true;
        } else {
            $this->setResponse('no ssh connection');
            return false;
        }
    }

    /**
     * @param $file
     * @param string $remoteDest
     * @return bool
     */
    function fileSend($file, $remoteDest = './') {
        if ($this->connected == 1) {
            if ((file_exists($file)) && is_readable($file)) {
                $filename = basename($file);
                $remoteDest = trim($remoteDest, '/');
                $remoteFile = $remoteDest . '/' . $filename;
                $send = ssh2_scp_send($this->session, $file, $remoteFile, 0644);
                if ($send) {
                    $this->setResponse('file sent to server');
                    return true;
                } else {
                    $this->setResponse('error sending file to remote host');
                    return false;
                }
            } else {
                $this->setResponse('the local file does not exist or is not readable');
                return false;
            }
        } else {
            $this->setResponse('no ssh connection');
            return false;
        }
    }

    /**
     * @param $file
     * @param bool $localDest
     * @return bool
     */
    function fileGet($file, $localDest = false) {
        if ($this->connected == 1) {
            $filename = basename($file);
            if (!$localDest) {
                $localDest = getcwd();
            }
            $path = realpath($localDest);
            if (@ssh2_scp_recv($this->session, $file, $path . '/' . $filename)) {
                user_error(__FUNCTION__ . '(): Unable to receive remote file, SCP may be disabled...');
                $this->setResponse('file received from server');
                return true;
            } else {
                $this->setResponse('error receiving file from remote host');
                return true;
            }
        } else {
            $this->setResponse('no ssh connection');
            return false;
        }
    }

    /**
     * @param $cmd
     * @return bool
     */
    function execute($cmd) {
        if ($this->connected != 1) {
            $response = 'no ssh connection';
            $this->setResponse($response);
            return false;
        }
        $end = $this->end;
        $_cmd = preg_replace('/;+$/', '', $cmd);
        $exec = $_cmd . '; echo "' . $end . '"';
        $stream = ssh2_exec($this->session, $exec);
        if (!$stream) {
            $response = 'unable to execute command';
            $this->setResponse($response);
            return false;
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
                $response = "the request sent took to long to process or the connection timed out at $timeout seconds";
                $this->setResponse($response);
                return false;
            }
        }
        $response = 'there was an error processing your request';
        $this->setResponse($response);
        return false;
    }

    /**
     * @param $cmd
     * @return bool|mixed
     */
    function shellExecute($cmd) {
        if ($this->connected != 1) {
            $response = 'no ssh connection';
            $this->setResponse($response);
            return false;
        }
        if (!$this->stream) {
            $this->stream = ssh2_shell($this->session, 'vt102', null, 180, 124, SSH2_TERM_UNIT_CHARS);
            if (!$this->stream) {
                $this->setResponse('unable to create a stream to shell');
                return false;
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
                $response = "the request sent took to long to process or the connection timed out at $timeout seconds";
                $this->setResponse($response);
                return false;
            }
        }
        $response = 'there was an error processing your request';
        $this->setResponse($response);
        return false;
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

}

//EOF