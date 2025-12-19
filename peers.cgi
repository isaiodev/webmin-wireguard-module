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

my $backend = &detect_backend();
if ($backend->{type} eq 'none') {
    &error($text{'backend_none'});
}

my $path = &get_config_path($backend, $iface);
&error($text{'config_missing'}) unless $path && -f $path;

my $parsed = &parse_wg_config($path);
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
print &ui_table_header([ $text{'peers_name'}, $text{'peers_publickey'},
    $text{'peers_allowedips'}, $text{'peers_endpoint'},
    $text{'peers_last_handshake'}, $text{'peers_rx'}, $text{'peers_tx'},
    $text{'index_actions'} ]);

foreach my $peer (@{$parsed->{peers}}) {
    my $pub = $peer->{'PublicKey'} || '';
    my $name = $peer->{'Name'} || '';
    my $allowed = $peer->{'AllowedIPs'} || '';
    my $endpoint = $peer->{'Endpoint'} || '';
    my $stat = $stats->{$pub} || {};
    my $hs = $stat->{'last_handshake'} || '';
    my $rx = $stat->{'rx'} || '';
    my $tx = $stat->{'tx'} || '';
    my $action = &can_edit()
        ? &ui_link("peer_delete.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub), $text{'peers_delete'})
        : '-';
    print &ui_table_row($name, $pub, $allowed, $endpoint, $hs, $rx, $tx, $action);
}
print &ui_table_end();

if (&can_edit()) {
    print &ui_form_start("peer_create.cgi", "post");
    print &ui_hidden("iface", $iface);
    print &ui_submit($text{'peers_add'});
    print &ui_form_end();
}

&ui_print_footer("index.cgi", $text{'index_title'});
