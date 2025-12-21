#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

my $iface = $in{'iface'};
my $pubkey = $in{'pubkey'};
my $name = $in{'name'} || '';

&error($text{'iface_invalid'}) unless &validate_iface($iface);
&error($text{'pubkey_invalid'}) unless &validate_key($pubkey);

my $conf_path = &get_peer_config_path($iface, $pubkey);
&error($text{'peer_config_missing'}) unless $conf_path && -f $conf_path;

open(my $fh, '<', $conf_path) || &error("Failed to read client config: $!");
local $/;
my $client_conf = <$fh>;
close($fh);

my $safe_name = $name;
$safe_name =~ s/[^A-Za-z0-9_.-]/_/g;
my $safe_pub = $pubkey;
$safe_pub =~ s/[^A-Za-z0-9_.-]/_/g;
my $base = $safe_name ? $safe_name : "$iface-$safe_pub";
my $filename = "$base.conf";

print "Content-Type: text/plain\n";
print "Content-Disposition: attachment; filename=\"$filename\"\n\n";
print $client_conf;
