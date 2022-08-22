<?php

namespace DeadUseful\OpenVzClient\Ssh;

use RuntimeException;

/**
 * SSH
 *
 * @note "PasswordAuthentication yes" must be set in the servers sshd_config
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
class Client
{
    private const DEFAULT_TIMEOUT = 30;

    /**
     * @var bool
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
    private $timeout = self::DEFAULT_TIMEOUT;

    /**
     * @var array
     */
    private $methods = [];

    /**
     * @var string
     */
    private $fingerprint;

    /**
     * @var string
     */
    private $pub_key_file;

    /**
     * @var string
     */
    private $private_key_file;

    /**
     * @var string
     */
    private $response;

    /**
     * @var string
     */
    private $result;

    function getResponse(): ?string
    {
        if ($this->response) {
            return $this->response;
        }
        return null;
    }

    function setResponse(string $response)
    {
        if ($response) {
            $this->response = $response;
        }
    }

    /**
     * @param string $host
     * @param int $port
     * @return bool|resource
     * @throws RuntimeException
     */
    function connect(string $host = 'localhost', int $port = 22): bool
    {
        if (!extension_loaded('ssh2')) {
            throw new RuntimeException('the ssh2 extension has not been loaded');
        }
        if ($this->isConnected()) {
            throw new RuntimeException('there may already be an active connection');
        }
        $connect = @ssh2_connect($host, $port, $this->methods);
        if (!$connect) {
            throw new RuntimeException('unable to establish connection');
        }
        $this->session = $connect;
        $this->finger($connect);
        return $connect;
    }

    function isConnected(): bool
    {
        if (empty($this->connected)) {
            throw new RuntimeException('no ssh connection');
        }
        return true;
    }

    function setConnected(bool $connected = true)
    {
        $this->connected = $connected;
    }

    public function finger($connect = null): string
    {
        if (!$connect) {
            $connect = $this->session();
        }
        $fingerprint = ssh2_fingerprint($connect, SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX);
        $this->fingerprint = $fingerprint;
        return $fingerprint;
    }

    /**
     * @throws RuntimeException
     */
    function session()
    {
        if (!is_resource($this->session)) {
            $type = gettype($this->session);
            throw new RuntimeException(__FUNCTION__ . "() expects parameter 1 to be resource, $type given");
        }
        return $this->session;
    }

    function setKeyFiles(string $private_key = 'id_rsa', string $pub_key = null)
    {
        if (!$pub_key) {
            $pub_key = $private_key . '.pub';
        }
        $this->private_key_file = $private_key;
        $this->pub_key_file = $pub_key;
    }

    /**
     * @throws RuntimeException
     */
    function auth(string $user = 'root', string $pass = '', $connect = null): bool
    {
        if (!$connect) {
            $connect = $this->session();
        }
        if ($this->pub_key_file && $this->private_key_file) {
            if (!file_exists($this->pub_key_file) || !file_exists($this->private_key_file)) {
                throw new RuntimeException('unable to find the key files');
            }
            $auth = ssh2_auth_pubkey_file($connect, $user, $this->pub_key_file, $this->private_key_file, $pass);
        } elseif ($pass) {
            $auth = ssh2_auth_password($connect, $user, $pass);
        } else {
            throw new RuntimeException('invalid credentials');
        }
        if (!$auth) {
            throw new RuntimeException('unable to authenticate');
        }
        $this->setConnected();
        $this->setResponse('connected and logged in');
        return $auth;
    }

    /**
     * @throws RuntimeException
     */
    function disconnect(): bool
    {
        if (!$this->isConnected()) {
            throw new RuntimeException('no ssh connection');
        }
        $this->setTimeout(1);
        $this->shellExecute('exit;');
        $this->session = null;
        $this->stream = null;
        $this->setConnected(false);
        $this->setResponse('ssh session closed');
        return true;
    }

    function setTimeout(int $seconds = 30)
    {
        $this->timeout = $seconds;
    }

    /**
     * @throws RuntimeException
     */
    function shellExecute($command)
    {
        $this->isConnected();
        if (!$this->stream) {
            $this->stream = ssh2_shell($this->session, 'vt102', null, 180, 124, SSH2_TERM_UNIT_CHARS);
            if (!$this->stream) {
                throw new RuntimeException('unable to create a stream to shell');
            }
        }
        $data = '';
        $time_start = time();
        $end = $this->end;
        $string = $command . '; echo "' . $end . '"' . PHP_EOL;
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
                throw new RuntimeException("the request sent took to long to process or the connection timed out at $timeout seconds");
            }
        }
        throw new RuntimeException('there was an error processing your request');
    }

    function cleanup(string $input): string
    {
        $end = $this->end;
        $string = '; echo "' . $end . '"';
        $str_replace = str_replace($string, '', $input);
        return str_replace($end, '', $str_replace);
    }

    function timeout(): int
    {
        return $this->timeout;
    }

    function fileSend(string $file, string $remoteDest = './'): bool
    {
        $this->isConnected();
        if ((file_exists($file)) && is_readable($file)) {
            $filename = basename($file);
            $remoteDest = trim($remoteDest, '/');
            $remoteFile = $remoteDest . '/' . $filename;
            $send = ssh2_scp_send($this->session, $file, $remoteFile, 0644);
            if ($send) {
                $this->setResponse('file sent to server');
                return true;
            }
            throw new RuntimeException('error sending file to remote host');
        }
        throw new RuntimeException('the local file does not exist or is not readable');
    }

    function fileGet(string $file, string $localDest = null): bool
    {
        $this->isConnected();
        $filename = basename($file);
        if (!$localDest) {
            $localDest = getcwd();
        }
        $path = realpath($localDest);
        if (@ssh2_scp_recv($this->session, $file, $path . '/' . $filename)) {
            $this->setResponse('file received from server');
            return true;
        }
        throw new RuntimeException('unable to receive remote file, SCP may be disabled...');
    }

    /**
     * @throws RuntimeException
     */
    function execute(string $command): bool
    {
        $this->isConnected();
        $end = $this->end;
        $_cmd = preg_replace('/;+$/', '', $command);
        $exec = $_cmd . '; echo "' . $end . '"';
        $stream = ssh2_exec($this->session, $exec);
        if (!$stream) {
            throw new RuntimeException('unable to execute command');
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
                throw new RuntimeException("the request sent took to long to process or the connection timed out at $timeout seconds");
            }
        }
        throw new RuntimeException('there was an error processing your request');
    }

    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    public function getResult(): string
    {
        return $this->result;
    }

    function setResult(string $result): bool
    {
        if ($result) {
            $this->result = $result;
        }
        return true;
    }

}

//EOF