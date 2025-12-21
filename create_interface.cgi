#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

&error_setup($text{'iface_create_failed'});

my $iface_name = $in{'iface_name'};
my $listen_port = $in{'listen_port'};
my $vpn_ip = $in{'vpn_ip'};

&validate_iface($iface_name) || &error($text{'iface_invalid'});

my $backend = &detect_backend();
my $conf_dir = $backend->{'config_dir'};
my $conf_path = "$conf_dir/$iface_name.conf";

-f $conf_path && &error("Configuration file $conf_path already exists.");

my $priv_key = &backquote_command("wg genkey");
chomp $priv_key;
my $pub_key = &backquote_command("echo ".&quote_escape($priv_key)." | wg pubkey");
chomp $pub_key;

my $conf_content = <<EOF;
[Interface]
PrivateKey = $priv_key
Address = $vpn_ip
ListenPort = $listen_port
# PublicKey = $pub_key
EOF

&lock_file($conf_path);
my $fh;
&open_tempfile($fh, ">$conf_path");
&print_tempfile($fh, $conf_content);
&close_tempfile($fh);
&unlock_file($conf_path);

&webmin_log("create", "iface", $iface_name);
&redirect("index.cgi");