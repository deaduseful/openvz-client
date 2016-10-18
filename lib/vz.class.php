<?php

/**
 * openVZ class.
 * @copyright Phurix 2009-2016.
 *
 * Example:
 * $vz = new vz();
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
 * */
class vz
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
     * @var ssh
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
     * @return string
     */
    function getResponse() {
        if ($this->response) {
            return $this->response;
        }
    }

    /**
     * @return int
     */
    function version() {
        return 1;
    }

    /**
     * @param $cmd
     * @return mixed
     */
    function shellExecute($cmd) {
        $this->result = $this->ssh->shellExecute($cmd);
        return $this->result;
    }

    /**
     * @param $server
     * @param $user
     * @param $pass
     * @param int $port
     * @return bool
     */
    function connect($server, $user, $pass, $port = 22) {
        if (!$this->ssh) {
            require_once 'ssh.class.php';
            $this->ssh = new ssh();
        }
        for ($i = 0; $i < $this->retry; $i++) {
            $connect = $this->ssh->connect($server, $port);
            if ($connect) {
                $homePath = $_SERVER['DOCUMENT_ROOT'] . DIRECTORY_SEPARATOR . '..';
                $keyFile = $homePath . DIRECTORY_SEPARATOR . '.ssh' . DIRECTORY_SEPARATOR . 'id_rsa';
                $this->ssh->setKeyFiles($keyFile);
                $auth = $this->ssh->auth($user, $pass);
                if ($auth) {
                    $this->connected = $connect;
                    return true;
                }
            }
        }
        $this->setResponse($this->ssh->getResponse());
        return false;
    }

    /**
     * @return mixed
     */
    function disconnect() {
        $this->connected = 0;
        $result = $this->ssh->disconnect();
        $this->ssh = null;
        return $result;
    }

    /**
     * @param string $user
     * @return bool|string
     */
    function su($user = 'root') {
        if (!$this->connected) {
            $response = 'no ssh connection';
            $this->setResponse($response);
            return false;
        }
        $this->ssh->settimeout(1);
        $this->shellExecute('sudo su ' . $user);
        $this->ssh->settimeout();
        $whoami = trim($this->shellExecute('whoami'));
        if ($whoami && $whoami == $user) {
            $cmd = 'export PATH=$PATH:/usr/sbin:/sbin';
            $this->shellExecute($cmd);
            $response = 'logged in as ' . $user;
            $this->setResponse($response);
            return $user;
        } else {
            $response = 'unable to login as ' . $user;
            throw new Exception($response);
        }
    }

    /**
     * @return bool|mixed
     */
    function bwmonreset() {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        $exec = '/sbin/iptables -Z';
        $result = $this->shellExecute($exec);
        if ($result) {
            $response = 'all bandwidth counters reset';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to reset bandwidth counters';
        throw new Exception($response);
    }

    /**
     * @param $ip
     * @return bool|mixed
     */
    function bwmon($ip) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (!$this->_valid_ip($ip)) {
            $response = 'invalid ip address';
            throw new Exception($response);
        }
        $cmd = "/sbin/iptables -L FORWARD -v -x -n | grep $ip";
        $result = $this->shellExecute($cmd);
        if ($result) {
            $response = 'bandwidth stats has been generated';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to generate bandwidth stats';
        throw new Exception($response);
    }

    /**
     * @param $ip
     * @return array|bool
     */
    function bwmonaddip($ip) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (!$this->_valid_ip($ip)) {
            $response = 'invalid ip address';
            throw new Exception($response);
        }
        $cmds = array();
        $cmds[] = "/sbin/iptables -A FORWARD -o eth0 -s $ip";
        $cmds[] = "/sbin/iptables -A FORWARD -i eth0 -d $ip";
        foreach ($cmds as $cmd) {
            $result[] = $this->shellExecute($cmd);
        }
        if (!empty($result)) {
            $response = 'bandwidth monitor added';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to add bandwidth monitor';
        throw new Exception($response);
    }

    /**
     * @param $ip
     * @return array|bool
     */
    function bwmondelip($ip) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (!$this->_valid_ip($ip)) {
            $response = 'invalid ip address';
            throw new Exception($response);
        }
        $cmds = array();
        $cmds[] = "/sbin/iptables -D FORWARD -o eth0 -s $ip";
        $cmds[] = "/sbin/iptables -D FORWARD -i eth0 -d $ip";
        foreach ($cmds as $cmd) {
            $result[] = $this->shellExecute($cmd);
        }
        if (!empty($result)) {
            $response = 'bandwidth monitor removed';
            $this->setResponse($response);
            return $result;
        }
        $response = 'unable to remove bandwidth monitor';
        throw new Exception($response);
    }

    /**
     * @param $veid
     * @return bool|string
     */
    function veid2ip($veid) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
            return false;
        }
        $cmd = "vzlist -o ctid,ip | grep $veid";
        $results = $this->shellExecute($cmd);
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
        throw new Exception($response);
    }

    /**
     * @return bool
     */
    function listos() {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        $exec = "ls -al /vz/template/cache/ | awk '{print $9}'";
        $listos = $this->shellExecute($exec);
        $osmatch = array();
        if (preg_match_all('/([a-z][\S]+\.gz)\s/i', $listos, $osmatch)) {
            $count = count($osmatch[1]);
            $result = array();
            for ($i = 1; $i < $count; $i++) {
                $result['t' . $i] = $osmatch[1][$i];
            }
            $response = 'virtual operating system templates listed';
            $this->setResponse($response);
            return $result;
        }
        $response = 'no operating systems found on hardware node';
        throw new Exception($response);
    }

    /**
     * @return array|bool
     */
    function listvps() {
        return $this->listvz();
    }

    /**
     * @return array|bool
     */
    function listvz() {
        $this->_isConnected();
        $listvz = $this->shellExecute('vzlist -a');
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
                throw new Exception($response);
            }
        }
        $response = 'unable to list virtual servers';
        throw new Exception($response);
    }

    /**
     * @param $veid
     * @return bool
     */
    function exists($veid) {
        $this->_isConnected();
        $this->_isVeid($veid);
        $listvz = $this->listvz();
        if (!empty($listvz) && array_key_exists($veid, $listvz)) {
            $response = 'veid exists';
            $this->setResponse($response);
            return true;
        }
        $response = 'veid not found on this server';
        throw new Exception($response);
    }

    /**
     * @param $veid
     * @param $data
     * @param bool $save
     * @return bool
     */
    function set($veid, $data, $save = false) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (preg_match('/([0-9]+)/', $veid)) {
            if (is_array($data)) {
                $result = array();
                foreach ($data as $dkey => $dval) {
                    if (!is_array($dkey) && !is_array($dval)) {
                        $cmd = "vzctl set $veid --$dkey $dval";
                        if ($save) {
                            $cmd .= ' --save';
                        }
                        $exe = $this->shellExecute($cmd);
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
            } else {
                $response = 'virtual server data not provided or invalid';
                throw new Exception($response);
            }
        } else {
            $response = 'invalid veid';
            throw new Exception($response);
        }
    }

    /**
     * @param $veid
     * @return bool
     */
    function suspend($veid) {
        return $this->stop($veid);
    }

    /**
     * @param $veid
     * @param bool $save
     * @return bool
     */
    function stop($veid, $save = true) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (preg_match('/([0-9]+)/', $veid)) {
            $timeout = $this->ssh->timeout();
            $this->ssh->settimeout(120);
            $exe = 'vzctl stop ' . $veid;
            if ($save) {
                $exe .= "; vzctl set $veid --onboot no --save";
            }
            $result = $this->shellExecute($exe);
            $this->ssh->settimeout($timeout);
            if (preg_match('/container was stopped/i', $result)) {
                $response = 'virtual server has been stopped';
                $this->setResponse($response);
                return true;
            } else {
                $response = 'Unable to stop virtual server';
                throw new Exception($response);
            }
        } else {
            $response = 'invalid veid';
            throw new Exception($response);
        }
    }

    /**
     * @param $veid
     * @return bool
     */
    function unsuspend($veid) {
        return $this->start($veid);
    }

    /**
     * @param $veid
     * @param bool $save
     * @return bool
     */
    function start($veid, $save = true) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (preg_match('/([0-9]+)/', $veid)) {
            $timeout = $this->ssh->timeout();
            $this->ssh->settimeout(60);
            $exe = 'vzctl start ' . $veid;
            if ($save) {
                $exe .= "; vzctl set $veid --onboot yes --save";
            }
            $result = $this->shellExecute($exe);
            $this->ssh->settimeout($timeout);
            if (preg_match('/container start in progress/i', $result)) {
                $response = 'virtual server has been started';
                $this->setResponse($response);
                return true;
            } else {
                $response = 'unable to start virtual server';
                throw new Exception($response);
            }
        } else {
            $response = 'invalid veid';
            throw new Exception($response);
        }
    }

    private function _isConnected() {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
    }

    private function _isVeid($veid) {
        $veid = (int)filter_var($veid, FILTER_VALIDATE_INT);
        if ($veid > 0) {
            return $veid;
        }
        $response = 'invalid veid';
        throw new Exception($response);
    }

    private function _exists($veid) {
        $exists = $this->exists($veid);
        return $exists;
    }

    /**
     * @param $veid
     * @return bool
     */
    function restart($veid) {
        $this->_isConnected();
        $this->_isVeid($veid);
        $this->_exists($veid);
        $timeout = $this->ssh->timeout();
        $this->ssh->settimeout(120);
        $exe = 'vzctl restart ' . $veid;
        $result = $this->shellExecute($exe);
        $this->ssh->settimeout($timeout);
        if (preg_match('/container start in progress/i', $result)) {
            $response = 'virtual server has been restarted';
            $this->setResponse($response);
            return true;
        }
        $response = 'unexpected response: ' . $result;
        throw new Exception($response);
    }

    /**
     * @param $veid
     * @param $os
     * @param $ip
     * @param null $pass
     * @param null $settings
     * @return bool
     */
    function create($veid, $os, $ip, $pass = null, $settings = null) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (preg_match('/([0-9]+)/', $veid)) {
            $exists = $this->exists($veid);
            if (!$exists) {
                $listos = $this->listos();
                if (($listos) && in_array($listos, $os)) {
                    if ($this->_valid_ip($ip)) {
                        if ((!$pass) || preg_match('/[^a-z0-9]+/i', $pass)) {
                            $pass = $this->_randompwd();
                        }
                        /** Everything provided up to this point has been verified and
                         * should be valid. We now create the VPS and apply the settings after */
                        $exe = 'vzctl create ' . $veid . ' --ostemplate ' . $os . '; ';
                        $exe .= 'vzctl set ' . $veid . ' --ipadd ' . $ip . ' --save; ';
                        $exe .= 'vzctl set ' . $veid . ' --onboot yes --save; ';
                        $exe .= 'vzctl exec ' . $veid . ' mount devpts /dev/pts -t devpts; ';
                        $exe .= 'vzctl exec ' . $veid . ' MAKEDEV tty; ';
                        $exe .= 'vzctl exec ' . $veid . ' MAKEDEV pty ';
                        $create_result = $this->shellExecute($exe);
                        if (preg_match('/container private area was created/i', $create_result)) {
                            if ($settings) {
                                $set_result = $this->set($veid, $settings, 1);
                            } else {
                                $set_result = 'no settings applied to virtual server';
                            }
                            $start = $this->start($veid);
                            $result = array();
                            $result['veid'] = $veid;
                            $result['operating_system'] = $os;
                            $result['ip_main'] = $ip;
                            $result['root_passwprd'] = $pass;
                            $result['settings'] = $set_result;
                            $result['running'] = $start;
                            $response = 'virtual server created';
                            $this->setResponse($response);
                            return $result;
                        } else {
                            $response = 'failed to create virtual server';
                            throw new Exception($response);
                        }
                    } else {
                        $response = 'invalid ip address';
                        throw new Exception($response);
                    }
                } else {
                    $response = 'operating system template not found or available';
                    throw new Exception($response);
                }
            } else {
                return $exists;
            }
        } else {
            $response = 'invalid veid';
            throw new Exception($response);
        }
    }

    /**
     * @param $veid
     * @return bool
     */
    function destroy($veid) {
        if (!$this->connected) {
            $response = 'no ssh connection';
            throw new Exception($response);
        }
        if (preg_match('/([0-9]+)/', $veid)) {
            $exists = $this->exists($veid);
            if ($exists) {
                $this->stop($veid);
                $result = $this->shellExecute('vzctl destroy ' . $veid);
                if (preg_match('/container private area was destroyed/i', $result)) {
                    $response = 'virtual server destroyed';
                    $this->setResponse($response);
                    return true;
                } else {
                    $response = 'failed to destroy virtual server';
                    throw new Exception($response);
                }
            } else {
                return $exists;
            }
        } else {
            $response = 'invalid veid';
            throw new Exception($response);
        }
    }

    /**
     * @param $ip
     * @return mixed
     */
    private function _valid_ip($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP);
    }

    /**
     * @param int $length
     * @return string
     */
    private function _randompwd($length = 8) {
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

}

//EOF