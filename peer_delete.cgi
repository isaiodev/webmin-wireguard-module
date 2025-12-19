#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

my $iface = $in{'iface'};
my $pubkey = $in{'pubkey'};

&error($text{'iface_invalid'}) unless &validate_iface($iface);
&error($text{'pubkey_invalid'}) unless &validate_key($pubkey);

my $backend = &detect_backend();
&error($text{'backend_none'}) if $backend->{type} eq 'none';
&error("Write access required") unless &can_edit();

my $path = &get_config_path($backend, $iface);
&error($text{'config_missing'}) unless $path && -f $path;

if ($in{'confirm'}) {
    &delete_peer_block($path, $pubkey);
    &ui_print_header(undef, $text{'peer_delete_title'}, "", undef, 1, 1);
    print &ui_subheading($text{'peer_deleted'});
    print &ui_link("peers.cgi?iface=".&urlize($iface), "Back to peers");
    &ui_print_footer("index.cgi", $text{'index_title'});
    exit;
}

&ui_print_header(undef, $text{'peer_delete_title'}, "", undef, 1, 1);
print &ui_subheading($text{'peer_delete_confirm'});
print &ui_form_start("peer_delete.cgi", "post");
print &ui_hidden("iface", $iface);
print &ui_hidden("pubkey", $pubkey);
print &ui_submit($text{'peers_delete'}, "confirm");
print &ui_link("peers.cgi?iface=".&urlize($iface), "Cancel");
print &ui_form_end();
&ui_print_footer("index.cgi", $text{'index_title'});
