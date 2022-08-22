<?php

namespace DeadUseful\OpenVzClient\OpenVz;

use Deaduseful\OpenvzClient\Ssh\Client as SshClient;
use RuntimeException;

/**
 * OpenVZ Client
 *
 * Example:
 * $vz = new Client();
 * print_r($vz->connect('server.domain.com', 'username', 'p4ssw0rd', 22));
 * print_r($vz->su());
 * print_r($vz->listvz());
 * print_r($vz->listos());
 * print_r($vz->exists('123'));
 * print_r($vz->create('123', 'centos-4-i386-minimal', '192.168.50.51', 'n3wr00tp4ssw0rd'));
 * print_r($vz->set('123', array('diskspace'=>'430209:433209', 'cpulimit'=>'20%')));
 * print_r($vz->stop('123'));
 * print_r($vz->start('123'));
 * print_r($vz->restart('123'));
 * print_r($vz->destroy('123'));
 *
 */
class Client
{
    /**
     * @var int
     */
    public $retry = 10;   // max amount of times to try connecting
    
    /**
     * @var resource
     */
    private $connected;
    
    /**
     * @var SshClient
     */
    private $ssh;
    
    /**
     * @var
     */
    private $response;
    
    /**
     * @var
     */
    private $result;

    public function getResponse(): ?string
    {
        if ($this->response) {
            return $this->response;
        }
        return null;
    }

    public function setResponse($response): bool
    {
        if ($response) {
            $this->response = $response;
        }
        return true;
    }

    public function connect(string $server, string $user, string $pass, int $port = 22): bool
    {
        for ($i = 0; $i < $this->retry; $i++) {
            $connect = $this->ssh->connect($server, $port);
            if ($connect) {
                $homePath = $_SERVER['DOCUMENT_ROOT'] . DIRECTORY_SEPARATOR . '..';
                $keyFile = $homePath . DIRECTORY_SEPARATOR . '.ssh' . DIRECTORY_SEPARATOR . 'id_rsa';
                $this->ssh->setKeyFiles($keyFile);
                $auth = $this->ssh->auth($user, $pass);
                if ($auth) {
                    $this->connected = $server;
                    return true;
                }
            }
        }
        $this->setResponse($this->ssh->getResponse());
        return false;
    }

    public function disconnect(): bool
    {
        $this->connected = 0;
        $result = $this->ssh->disconnect();
        $this->ssh = null;
        return $result;
    }

    /**
     * @throws RuntimeException
     */
    public function su(string $user = 'root'): string
    {
        $this->_isConnected();
        $this->_setTimeout(1);
        $this->_shellExecute('sudo su ' . $user);
        $this->_setTimeout();
        $whoami = trim($this->_shellExecute('whoami'));
        if ($whoami && $whoami == $user) {
            $command = 'export PATH=$PATH:/usr/sbin:/sbin';
            $this->_shellExecute($command);
            $response = 'logged in as ' . $user;
            $this->setResponse($response);
            return $user;
        } else {
            $response = 'unable to login as ' . $user;
            throw new RuntimeException($response);
        }
    }

    private function _setTimeout(int $timeout = 60)
    {
        $this->ssh->setTimeout($timeout);
    }

    private function _shellExecute(string $command)
    {
        $this->result = $this->ssh->shellExecute($command);
        return $this->result;
    }

    /**
     * @return bool|mixed
     * @throws RuntimeException
     */
    function bwmonreset()
    {
        $this->_isConnected();
        $exec = '/sbin/iptables -Z';
        $result = $this->_shellExecute($exec);
        if ($result) {
            $response = 'all bandwidth counters reset';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to reset bandwidth counters';
        throw new RuntimeException($response);
    }

    /**
     * @param $ip
     * @return bool|mixed
     * @throws RuntimeException
     */
    function bwmon($ip)
    {
        $this->_isConnected();
        $this->_isValidIp($ip);
        $command = "/sbin/iptables -L FORWARD -v -x -n | grep $ip";
        $result = $this->_shellExecute($command);
        if ($result) {
            $response = 'bandwidth stats has been generated';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to generate bandwidth stats';
        throw new RuntimeException($response);
    }

    private function _isValidIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
        }
        $response = 'invalid ip address';
        throw new RuntimeException($response);
    }

    /**
     * @throws RuntimeException
     */
    public function bandwidthMonitorAddIp(string $ip): array
    {
        $this->_isConnected();
        $this->_isValidIp($ip);
        $commands = array();
        $commands[] = "/sbin/iptables -A FORWARD -o eth0 -s $ip";
        $commands[] = "/sbin/iptables -A FORWARD -i eth0 -d $ip";
        foreach ($commands as $command) {
            $result[] = $this->_shellExecute($command);
        }
        if (!empty($result)) {
            $response = 'bandwidth monitor added';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to add bandwidth monitor';
        throw new RuntimeException($response);
    }

    /**
     * @param $ip
     * @return array|bool
     * @throws RuntimeException
     */
    function bwmondelip($ip)
    {
        $this->_isConnected();
        $this->_isValidIp($ip);
        $commands = array();
        $commands[] = "/sbin/iptables -D FORWARD -o eth0 -s $ip";
        $commands[] = "/sbin/iptables -D FORWARD -i eth0 -d $ip";
        foreach ($commands as $command) {
            $result[] = $this->_shellExecute($command);
        }
        if (!empty($result)) {
            $response = 'bandwidth monitor removed';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to remove bandwidth monitor';
        throw new RuntimeException($response);
    }

    /**
     * @param $veid
     * @return bool|string
     * @throws RuntimeException
     */
    function veid2ip($veid)
    {
        $this->_isConnected();
        $command = "vzlist -o ctid,ip | grep $veid";
        $results = $this->_shellExecute($command);
        if ($results) {
            foreach ($results as $result) {
                if (preg_match("/^\s+$veid\s+(.+?)$/i", $result, $matches)) {
                    $result = "IPs " . $matches[1];
                    $response = 'found ip address data';
                    $this->setResponse($response);
                    return $result;
                }
            }
        }
        $response = 'unable to gather ip address data';
        throw new RuntimeException($response);
    }

    /**
     * @return resource
     * @throws RuntimeException
     */
    private function _isConnected()
    {
        if (empty($this->connected)) {
            $response = 'no ssh connection';
            throw new RuntimeException($response);
        }
        return $this->connected;
    }

    /**
     * @return bool
     * @throws RuntimeException
     */
    public function listos()
    {
        $this->_isConnected();
        $dir_template_cache = '/vz/template/cache/';
        $exec = "ls -al $dir_template_cache | awk '{print $9}'";
        $listos = $this->_shellExecute($exec);
        $match = array();
        if (preg_match_all('/([a-z][\S]+\.gz)\s/i', $listos, $match)) {
            $count = count($match[1]);
            $result = array();
            for ($i = 1; $i < $count; $i++) {
                $os = $match[1][$i];
                $result['t' . $i] = $os;
            }
            $response = 'virtual operating system templates listed';
            $this->setResponse($response);
            return $result;
        }
        $response = 'no operating systems found on hardware node';
        throw new RuntimeException($response);
    }

    /**
     * @return array|bool
     */
    function listvps()
    {
        return $this->listvz();
    }

    /**
     * @return array|bool
     * @throws RuntimeException
     */
    function listvz()
    {
        $this->_isConnected();
        $listvz = $this->_shellExecute('vzlist -a');
        $match = array();
        $pattern = '/([0-9]+)\s+([0-9\-]+)\s+([a-z]+)\s+([0-9\.]+)\s+([\S]+)/';
        if (preg_match_all($pattern, $listvz, $match)) {
            if (((!empty($match)) && is_array($match)) && count($match) == 6) {
                $result = array();
                $count = count($match[1]);
                for ($i = 0; $i < $count; $i++) {
                    $veid = $match[1][$i];
                    $result[$veid]['veid'] = $veid;
                    $result[$veid]['nproc'] = $match[2][$i];
                    $result[$veid]['status'] = $match[3][$i];
                    $result[$veid]['ip_addr'] = $match[4][$i];
                    $result[$veid]['hostname'] = $match[5][$i];
                }
                $response = 'virtual servers listed';
                $this->setResponse($response);
                return $result;
            } else {
                $response = 'unable to determine virtual servers';
                throw new RuntimeException($response);
            }
        }
        $response = 'unable to list virtual servers';
        throw new RuntimeException($response);
    }

    /**
     * @throws RuntimeException
     */
    function set(int $veid, array $settings = [], bool $save = false): array
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        if (!is_array($settings)) {
            $settings = unserialize(urldecode($settings));
        }
        if (!is_array($settings) || empty($settings)) {
            $response = 'virtual server data not provided or invalid';
            throw new RuntimeException($response);
        }
        $result = array();
        foreach ($settings as $dkey => $dval) {
            if (!is_array($dkey) && !is_array($dval)) {
                $command = "vzctl set $veid --$dkey $dval";
                if ($save) {
                    $command .= ' --save';
                }
                $exe = $this->_shellExecute($command);
                if (preg_match('/saved parameters/i', $exe)) {
                    $result[$dkey] = 1;
                } else {
                    $result[$dkey] = 0;
                }
            } else {
                $result[$dkey] = 0;
            }
        }
        $response = 'settings applied to virtual server';
        $this->setResponse($response);
        return $result;

    }

    /**
     * @param $veid
     * @return int
     * @throws RuntimeException
     */
    private function _isVeid($veid)
    {
        $veid = (int)filter_var($veid, FILTER_VALIDATE_INT);
        if ($veid > 0) {
            return $veid;
        }
        $response = 'invalid veid';
        throw new RuntimeException($response);
    }

    /**
     * @param $veid
     * @return bool
     */
    function suspend($veid)
    {
        return $this->stop($veid);
    }

    /**
     * @param $veid
     * @param bool $save
     * @return bool
     * @throws RuntimeException
     */
    function stop($veid, $save = true)
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        $timeout = $this->_getTimeout();
        $this->_setTimeout(120);
        $exe = 'vzctl stop ' . $veid;
        if ($save) {
            $exe .= "; vzctl set $veid --onboot no --save";
        }
        $result = $this->_shellExecute($exe);
        $this->_setTimeout($timeout);
        if (preg_match('/container is not running/i', $result)) {
            $response = 'virtual server already stopped';
            $this->setResponse($response);
            return true;
        }
        if (preg_match('/config file does not exist/i', $result)) {
            $response = 'virtual server config file does not exist';
            $this->setResponse($response);
            return true;
        }
        if (!preg_match('/container was stopped/i', $result)) {
            user_error($result);
            $response = 'unable to stop virtual server';
            throw new RuntimeException($response);
        }
        $response = 'virtual server has been stopped';
        $this->setResponse($response);
        return true;
    }

    /**
     * @return int
     */
    private function _getTimeout()
    {
        return $this->ssh->timeout();
    }

    /**
     * @param $veid
     * @return bool
     */
    function unsuspend($veid)
    {
        return $this->start($veid);
    }

    /**
     * @param $veid
     * @param bool $save
     * @return bool
     * @throws RuntimeException
     */
    function start($veid, $save = true)
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        $timeout = $this->_getTimeout();
        $this->_setTimeout(60);
        $exe = 'vzctl start ' . $veid;
        if ($save) {
            $exe .= "; vzctl set $veid --onboot yes --save";
        }
        $result = $this->_shellExecute($exe);
        $this->_setTimeout($timeout);
        $response = null;
        if (preg_match('/container is already running/i', $result)) {
            $response = 'virtual server is already running';
        }
        if (preg_match('/container start in progress/i', $result)) {
            $response = 'virtual server has been started';
        }
        if ($response) {
            $this->setResponse($response);
            return true;
        }
        user_error($result);
        $response = 'unable to start virtual server';
        throw new RuntimeException($response);
    }

    /**
     * @param $veid
     * @return bool
     * @throws RuntimeException
     */
    function restart($veid)
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        $this->_veidExists($veid);
        $timeout = $this->_getTimeout();
        $this->_setTimeout(120);
        $exe = 'vzctl restart ' . $veid;
        $result = $this->_shellExecute($exe);
        $this->_setTimeout($timeout);
        if (preg_match('/container start in progress/i', $result)) {
            $response = 'virtual server has been restarted';
            $this->setResponse($response);
            return true;
        }
        $response = 'unexpected response: ' . $result;
        throw new RuntimeException($response);
    }

    /**
     * @param $veid
     * @return bool
     * @throws RuntimeException
     */
    private function _veidExists($veid)
    {
        $exists = $this->exists($veid);
        return $exists;
    }

    /**
     * @param $veid
     * @return bool
     * @throws RuntimeException
     */
    function exists($veid)
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        $listvz = $this->listvz();
        if (!empty($listvz) && array_key_exists($veid, $listvz)) {
            $response = 'veid exists';
            $this->setResponse($response);
            return true;
        }
        $server = $this->_isConnected();
        $response = "veid '$veid' not found on server '$server'";
        throw new RuntimeException($response);
    }

    /**
     * @param $veid
     * @param $ip
     * @param $os
     * @param null $pass
     * @param array $settings
     * @return array
     * @throws RuntimeException
     */
    function create($veid, $ip, $os, $pass = null, array $settings = []): array
    {
        $this->_isConnected();
        $this->_isValidIp($ip);
        $this->_isVeid($veid);
        $this->stop($veid);
        $this->osTemplateCheck($os);
        if ((!$pass) || preg_match('/[^a-z0-9]+/i', $pass)) {
            $pass = $this->_getRandomPassword();
        }
        $hostname = sprintf('vps%s.%s', $veid, trim(`hostname`));
        if (!is_array($settings)) {
            $settings = unserialize(urldecode($settings));
        }
        /** Everything provided up to this point has been verified and
         * should be valid. We now create the VPS and apply the settings after */
        $settings['ostemplate'] = $os;
        $settings['layout'] = 'simfs';
        $settings['ipadd'] = $ip;
        $settings['hostname'] = $hostname;
        $settings['onboot'] = 'yes';
        $settings_keys = 'diskspace,diskinodes,ostemplate,layout,ipadd,hostname';
        $allowed_flags = explode(',', $settings_keys);
        $flags = [];
        $sets = [];
        foreach ($settings as $flag => $setting) {
            if (in_array($flag, $allowed_flags)) {
                $flags[] = "--$flag $setting";
            }
            $sets[] = "--$flag $setting";
        }
        $flags = implode(' ', $flags);
        $exe = "vzctl create $veid $flags;";
        foreach ($sets as $set) {
            $exe .= "vzctl set $veid $set --save;";
        }
        $exe .= 'vzctl exec ' . $veid . ' mount devpts /dev/pts -t devpts; ';
        $exe .= 'vzctl exec ' . $veid . ' MAKEDEV tty; ';
        $exe .= 'vzctl exec ' . $veid . ' MAKEDEV pty ';
        $create_result = $this->_shellExecute($exe);
        if (!preg_match('/container private area was created/i', $create_result)) {
            error_log($create_result);
            $response = 'failed to create virtual server';
            throw new RuntimeException($response);
        }
        $start = $this->start($veid);
        $result = array();
        $result['veid'] = $veid;
        $result['operating_system'] = $os;
        $result['ip_main'] = $ip;
        $result['root_password'] = $pass;
        $result['running'] = $start;
        $response = 'virtual server created';
        $this->setResponse($response);
        return $result;
    }

    /**
     * @param $os
     * @return bool
     * @throws RuntimeException
     */
    function osTemplateCheck($os): bool
    {
        $this->_isConnected();
        $osFilename = $os . '.tar.gz';
        $osPath = '/vz/template/cache';
        $osFile = $osPath . DIRECTORY_SEPARATOR . $osFilename;
        $osUrl = 'http://download.openvz.org/template/precreated';
        $osUrlFile = "$osUrl/$osFilename";
        if ($this->_fileExists($osFile)) {
            return true;
        }
        $this->_fileCopy($osUrlFile, $osFile);
        if ($this->_fileExists($osFile)) {
            return true;
        }
        $response = "unable to find '$os'";
        throw new RuntimeException($response);
    }

    /**
     * @param $file
     * @return int
     * @throws RuntimeException
     */
    private function _fileExists($file)
    {
        $this->_isConnected();
        $command = "[[ -e $file ]] && echo true || false";
        $result = $this->_shellExecute($command);
        return preg_match('/true/i', $result);
    }

    /**
     * @param $source
     * @param $dest
     * @param int $timeout
     * @return mixed
     * @throws RuntimeException
     */
    private function _fileCopy($source, $dest, $timeout = 9000)
    {
        $this->_isConnected();
        $_timeout = $this->_getTimeout();
        $this->_setTimeout($timeout);
        $command = "wget $source -O $dest -t 5 -T $timeout";
        $result = $this->_shellExecute($command);
        $this->_setTimeout($_timeout);
        return $result;
    }

    /**
     * @param int $length
     * @return string
     */
    private function _getRandomPassword($length = 8)
    {
        $salt = 'abchefghjkmnpqrstuvwxyz0123456789';
        srand((double)microtime() * 1000000);
        $i = 0;
        $pass = false;
        while ($i <= $length) {
            $num = rand() % 33;
            $tmp = substr($salt, $num, 1);
            $pass = $pass ? $pass . $tmp : $tmp;
            $i++;
        }
        return $pass;
    }

    /**
     * @param $veid
     * @param $confirm
     * @return bool
     *
     * @throws RuntimeException if container was not destroyed
     */
    function destroy($veid, $confirm = false)
    {
        if (!$confirm) {
            $response = 'unconfirmed destroy';
            throw new RuntimeException($response);
        }
        $this->_isConnected();
        $this->_isVeid($veid);
        $this->_veidExists($veid);
        $this->stop($veid);
        $result = $this->_shellExecute('vzctl destroy ' . $veid);
        if (!preg_match('/container private area was destroyed/i', $result)) {
            $response = 'failed to destroy virtual server';
            throw new RuntimeException($response);
        }
        $response = 'virtual server destroyed';
        $this->setResponse($response);
        return true;
    }

    /**
     * @param $veid
     * @param $command
     * @return mixed
     */
    function exec($veid, $command)
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        $this->_veidExists($veid);
        $this->result = $this->_shellExecute("vzctl exec $veid $command");
        return $this->result;
    }

    /**
     * vzmigrate
     *
     * @see https://openvz.org/Checkpointing_and_live_migration
     *
     * @param $host
     * @param $veid
     * @param int $port
     * @throws RuntimeException
     */
    function migrate($host, $veid, $port = 2222)
    {
        $this->_isConnected();
        $this->_isVeid($veid);
        $this->_veidExists($veid);
        $command = "vzmigrate --live $host $veid --ssh='-p $port' --nodeps=cpu";
        $this->result = $this->_shellExecute($command);
        return $this->result;
    }
}

//EOF