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

sub peer_config_base_dir {
    if (defined &get_module_config_directory) {
        return &get_module_config_directory();
    }
    if ($ENV{'WEBMIN_CONFIG'}) {
        return "$ENV{'WEBMIN_CONFIG'}/wireguard";
    }
    return "/etc/webmin/wireguard";
}

sub peer_config_dir {
    return peer_config_base_dir()."/peer-configs";
}

sub peer_config_path {
    my ($iface_name, $key) = @_;
    return undef unless $iface_name && $key;
    my $safe = $key;
    $safe =~ s/[^A-Za-z0-9_.-]/_/g;
    return peer_config_dir()."/$iface_name-$safe.conf";
}

my $backend = &detect_backend();
&error($text{'backend_none'}) if $backend->{type} eq 'none';
&error("Write access required") unless &can_edit();

my $path = &get_config_path($backend, $iface);
&error($text{'config_missing'}) unless $path && -f $path;

if ($in{'confirm'}) {
    &delete_peer_block($path, $pubkey);
    my $conf_path = &peer_config_path($iface, $pubkey);
    unlink $conf_path if $conf_path && -f $conf_path;
    &ui_print_header(undef, $text{'peer_delete_title'}, "", undef, 1, 1);
    print &ui_subheading($text{'peer_deleted'});
    print &ui_link("peers.cgi?iface=".&urlize($iface), $text{'peers_back'});
    &ui_print_footer("index.cgi", $text{'index_title'});
    exit;
}

&ui_print_header(undef, $text{'peer_delete_title'}, "", undef, 1, 1);
print &ui_subheading($text{'peer_delete_confirm'});
print &ui_form_start("peer_delete.cgi", "post");
print &ui_hidden("iface", $iface);
print &ui_hidden("pubkey", $pubkey);
print &ui_submit($text{'peers_delete'}, "confirm");
print &ui_link("peers.cgi?iface=".&urlize($iface), $text{'peers_cancel'});
print &ui_form_end();
&ui_print_footer("index.cgi", $text{'index_title'});
