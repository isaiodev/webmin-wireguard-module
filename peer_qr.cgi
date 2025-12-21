#!/usr/bin/perl
use strict;
use warnings;
use MIME::Base64 qw(decode_base64);

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

my $iface = $in{'iface'};
my $pubkey = $in{'pubkey'};
my $name = $in{'name'} || '';

&error($text{'iface_invalid'}) unless &validate_iface($iface);
&error($text{'pubkey_invalid'}) unless &validate_key($pubkey);
&error($text{'qr_disabled'}) unless $config{'enable_qr'};
&error($text{'qr_missing'}) unless &has_command('qrencode');

my $conf_path = &get_peer_config_path($iface, $pubkey);
&error($text{'peer_config_missing'}) unless $conf_path && -f $conf_path;

open(my $fh, '<', $conf_path) || &error("Failed to read client config: $!");
local $/;
my $client_conf = <$fh>;
close($fh);

my $qr_cmd = "echo ".&quote_escape($client_conf)." | qrencode -t PNG -o - | base64 -w 0";
my $qr_base64 = &backquote_command("$qr_cmd 2>/dev/null");
&error($text{'qr_failed'}) if !$qr_base64 || $? != 0;
chomp $qr_base64;

if ($in{'raw'}) {
    print "Content-Type: image/png\n\n";
    print decode_base64($qr_base64);
    exit;
}

my $title = $name ? "$text{'peer_qr_title'} $name" : $text{'peer_qr_title'};
&ui_print_header(undef, $title, "", undef, 1, 1);
print &ui_subheading($title);
print "<div style='text-align:center;'>";
print "<img src='data:image/png;base64,$qr_base64' alt='QR Code' style='max-width:300px;'/>";
print "</div>";
print "<br>";
print &ui_link("peers.cgi?iface=".&urlize($iface), $text{'peers_back'});
&ui_print_footer("index.cgi", $text{'index_title'});
