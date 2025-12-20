#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();

&ReadParse();
my $iface = $in{'iface'};

if (!&validate_iface($iface)) {
    &error($text{'iface_invalid'});
}

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
if ($backend->{type} eq 'none') {
    &error($text{'backend_none'});
}

my $path = &get_config_path($backend, $iface);
my $parsed;
if ($backend->{type} eq 'docker') {
    $parsed = &parse_wg_config_docker($backend, $iface);
} elsif ($path && -f $path) {
    $parsed = &parse_wg_config($path);
}
&error($text{'config_missing'}) unless $parsed;
my $stats = &get_peer_stats($backend, $iface);

&ui_print_header(undef, "$text{'peers_title'} $iface", "", undef, 1, 1);
print &ui_subheading("$text{'index_backend'}: $backend->{detail}");

my $status_line = '-';
if ($backend->{type} eq 'host') {
    my $out = &backquote_command("/bin/systemctl is-active wg-quick\@$iface 2>/dev/null");
    $status_line = ($? == 0) ? 'active' : 'inactive';
} else {
    my $out = &backquote_command("docker inspect -f '{{.State.Running}}' ".&quote_escape($backend->{container})." 2>/dev/null");
    $status_line = ($out =~ /true/) ? 'container running' : 'stopped';
}

print &ui_table_start($text{'index_status'}, undef, 2);
print &ui_table_row($text{'index_status'}, $status_line);
print &ui_table_end();

print &ui_table_start($text{'index_peers'}, "width=100%", 8);
print "<tr><th>$text{'peers_name'}</th><th>$text{'peers_publickey'}</th>".
      "<th>$text{'peers_allowedips'}</th><th>$text{'peers_endpoint'}</th>".
      "<th>$text{'peers_last_handshake'}</th><th>$text{'peers_rx'}</th>".
      "<th>$text{'peers_tx'}</th><th>$text{'index_actions'}</th></tr>";

my $qr_enabled = $config{'enable_qr'} && &has_command('qrencode');
foreach my $peer (@{$parsed->{peers}}) {
    my $pub = $peer->{'PublicKey'} || '';
    my $name = $peer->{'Name'} || '';
    my $allowed = $peer->{'AllowedIPs'} || '';
    my $endpoint = $peer->{'Endpoint'} || '';
    my $stat = $stats->{$pub} || {};
    my $hs = $stat->{'last_handshake'} || '';
    my $rx = $stat->{'rx'} || '';
    my $tx = $stat->{'tx'} || '';
    my @actions;
    if (&can_edit()) {
        push @actions, &ui_link("peer_delete.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub), $text{'peers_delete'});
    }
    my $conf_path = &peer_config_path($iface, $pub);
    if ($conf_path && -f $conf_path) {
        push @actions, &ui_link("peer_download.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub)."&name=".&urlize($name), $text{'peers_download'});
        if ($qr_enabled) {
            push @actions, &ui_link("peer_qr.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub)."&name=".&urlize($name), $text{'peers_qr'});
        }
    }
    my $action = @actions ? join(" | ", @actions) : '-';
    print &ui_table_row($name, $pub, $allowed, $endpoint, $hs, $rx, $tx, $action);
}
print &ui_table_end();

if (&can_edit()) {
    print "<br>";
    print &ui_link("peer_create.cgi?iface=".&urlize($iface), $text{'peers_add'});
}

&ui_print_footer("index.cgi", $text{'index_title'});
