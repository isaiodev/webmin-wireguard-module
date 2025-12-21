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
my $parsed;
if ($backend->{type} eq 'docker') {
    $parsed = &parse_wg_config_docker($backend, $iface);
} elsif ($path && -f $path) {
    $parsed = &parse_wg_config($path);
}
&error($text{'config_missing'}) unless $parsed;

my $peer;
foreach my $p (@{$parsed->{peers}}) {
    if (($p->{'PublicKey'} || '') eq $pubkey) {
        $peer = $p;
        last;
    }
}
&error($text{'peer_not_found'}) unless $peer;

if ($in{'save'}) {
    &error($text{'allowedips_invalid'}) unless &validate_allowed_ips($in{'allowedips'});
    my $keepalive = $in{'keepalive'};
    &error("Invalid keepalive") if $keepalive && $keepalive !~ /^\d+$/;

    my @block;
    push @block, "[Peer]";
    if ($in{'name'}) {
        my $name = $in{'name'};
        $name =~ s/[\r\n]//g;
        push @block, "# Name: $name";
    }
    push @block, "PublicKey = $pubkey";
    push @block, "AllowedIPs = ".$in{'allowedips'};
    push @block, "Endpoint = ".$in{'endpoint'} if $in{'endpoint'};
    push @block, "PresharedKey = ".$in{'preshared'} if $in{'preshared'};
    push @block, "PersistentKeepalive = ".$in{'keepalive'} if $in{'keepalive'};

    if ($backend->{type} eq 'docker') {
        my $lines = $parsed->{lines} || [];
        my $out = &update_peer_lines($lines, $pubkey, \@block);
        if (!&write_docker_config($backend, $iface, $out)) {
            my $err = &last_error();
            my $msg = $text{'peer_write_failed'};
            $msg .= ": $err" if $err;
            &error($msg);
        }
    } else {
        if ($path && !-w $path) {
            &error($text{'peer_write_failed'}.": $!");
        }
        my $lines = &read_file_lines($path);
        my $out = &update_peer_lines($lines, $pubkey, \@block);
        &save_config_lines($path, $out);
    }

    my $client_priv_key;
    my $peer_conf_path = &get_peer_config_path($iface, $pubkey);
    if (-f $peer_conf_path) {
        my $client_config_content = &read_file_contents($peer_conf_path);
        if ($client_config_content =~ /PrivateKey\s*=\s*(.*)/) {
            $client_priv_key = $1;
        }
    }

    my %peer_data = (
        'PrivateKey'   => $client_priv_key,
        'PublicKey'    => $pubkey,
        'AllowedIPs'   => $in{'allowedips'},
        'PresharedKey' => $in{'preshared'},
        'DNS'          => $config{'default_dns'} || '',
    );
    my $server_pub = '';
    if (my $int_priv = $parsed->{interface}->{'PrivateKey'}) {
        my $cmd = "/bin/sh -c 'echo ".&quote_escape($int_priv)." | /usr/bin/wg pubkey'";
        $server_pub = &backquote_command("$cmd 2>/dev/null");
        chomp $server_pub;
    }
    my %server_data = (
        'PublicKey' => $server_pub,
        'Endpoint'  => $config{'default_endpoint'} || '',
    );

    &create_peer_config_file($iface, \%peer_data, \%server_data);

    &ui_print_header(undef, $text{'peer_edit_title'}, "", undef, 1, 1);
    print &ui_subheading($text{'peer_updated'});
    print &ui_link("peers.cgi?iface=".&urlize($iface), $text{'peers_back'});
    &ui_print_footer("index.cgi", $text{'index_title'});
    exit;
}

&ui_print_header(undef, $text{'peer_edit_title'}, "", undef, 1, 1);
print &ui_subheading($text{'peer_edit_title'});

print &ui_form_start("peer_edit.cgi", "post");
print &ui_hidden("iface", $iface);
print &ui_hidden("pubkey", $pubkey);
print &ui_table_start($text{'peer_edit_title'}, undef, 2);
print &ui_table_row($text{'peers_name'},
    &ui_textbox("name", $peer->{'Name'} || '', 40));
print &ui_table_row($text{'peers_publickey'},
    &ui_textbox("pubkey_display", $pubkey, 55, 1));
print &ui_table_row($text{'peers_allowedips'},
    &ui_textbox("allowedips", $peer->{'AllowedIPs'} || '', 40));
print &ui_table_row($text{'peers_endpoint'},
    &ui_textbox("endpoint", $peer->{'Endpoint'} || '', 40));
print &ui_table_row("Preshared key",
    &ui_textbox("preshared", $peer->{'PresharedKey'} || '', 45));
print &ui_table_row("Persistent keepalive",
    &ui_textbox("keepalive", $peer->{'PersistentKeepalive'} || '', 5)." seconds");
print &ui_table_end();
print &ui_submit($text{'peer_update'}, "save");
print &ui_form_end();
&ui_print_footer("index.cgi", $text{'index_title'});
