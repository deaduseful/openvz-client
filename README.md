# An OpenVz Client

An OpenVz client using the ssh2 client.

## Installation

`composer require deaduseful/openvz-client`

### Prerequisites

* On Linux:

```shell
    yum install libssh2-devel
    pear config-set preferred_state beta
    pecl install ssh2
    pear config-set preferred_state stable
```

On Mac OS X:

```shell
    brew install libssh2
    pecl install ssh2-1.1.2
```

### Usage

The server must have "PasswordAuthentication yes" set in the sshd_config.

### OpenVz Client Usage
```php
    $vz = new OpenVz/Client();
    print_r($vz->connect('server.domain.com', 'username', 'p4ssw0rd', 22));
    print_r($vz->su());
    print_r($vz->listvz());
    print_r($vz->listos());
    print_r($vz->exists('123'));
    print_r($vz->create('123', 'centos-4-i386-minimal', '192.168.50.51', 'n3wr00tp4ssw0rd'));
    print_r($vz->set('123', array('diskspace'=>'430209:433209', 'cpulimit'=>'20%')));
    print_r($vz->stop('123'));
    print_r($vz->start('123'));
    print_r($vz->restart('123'));
    print_r($vz->destroy('123'));
```

### SSH Client usage

```php
    $ssh = new Ssh/Client();
    $ssh->connect('host');
    $ssh->auth('user', 'password');
    $ssh->shellExecute('ps auxfc; ls');
    $ssh->disconnect();
```

## About

> A [dead useful](https://deaduseful.com/) project for [Phurix Web Hosting](https://phurix.co.uk/).

Copyright (c) 2004-2022 [James Wade](https://wade.be/)

