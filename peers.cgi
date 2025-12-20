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

print "<div id='qrModal' style='display:none; position:fixed; z-index:1000; left:0; top:0; width:100%; height:100%; background-color:rgba(0,0,0,0.5);'>";
print "<div style='background-color:white; margin:10% auto; padding:20px; border:1px solid #888; width:320px; text-align:center;'>";
print "<span onclick='closeQR()' style='color:#aaa; float:right; font-size:28px; font-weight:bold; cursor:pointer;'>&times;</span>";
print "<h3 id='qrTitle'>QR Code</h3>";
print "<img id='qrImg' src='' alt='QR Code' style='max-width:260px;'/>";
print "</div></div>";
print "<script>function showQR(url,title){var m=document.getElementById('qrModal');var i=document.getElementById('qrImg');var t=document.getElementById('qrTitle');i.src=url;t.textContent=title||'QR Code';m.style.display='block';} function closeQR(){document.getElementById('qrModal').style.display='none';document.getElementById('qrImg').src='';}</script>";

print "<div class='table-responsive'>";
print "<table data-table-type='ui-table' class='table table-striped table-condensed table-subtable' width='100%'>";
print "<thead><tr><th>$text{'peers_name'}</th><th>$text{'peers_publickey'}</th>".
      "<th>$text{'peers_allowedips'}</th><th>$text{'peers_endpoint'}</th>".
      "<th>$text{'peers_last_handshake'}</th><th>$text{'peers_rx'}</th>".
      "<th>$text{'peers_tx'}</th><th>$text{'index_actions'}</th></tr></thead>";
print "<tbody>";

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
        push @actions, "<a class='btn btn-default btn-tiny' href='peer_edit.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub)."'>$text{'peers_edit'}</a>";
        push @actions, "<a class='btn btn-danger btn-tiny' href='peer_delete.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub)."'>$text{'peers_delete'}</a>";
    }
    push @actions, "<a class='btn btn-default btn-tiny' href='peer_download.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub)."&name=".&urlize($name)."'>$text{'peers_download'}</a>";
    if ($qr_enabled) {
        my $qr_url = "peer_qr.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($pub)."&name=".&urlize($name)."&raw=1";
        push @actions, "<a class='btn btn-default btn-tiny' href='#' onclick=\"showQR('$qr_url','QR - ".&html_escape($name || $pub)."'); return false;\">$text{'peers_qr'}</a>";
    }
    my $action = @actions ? join(" | ", @actions) : '-';
    print "<tr>";
    print "<td>".&html_escape($name)."</td>";
    print "<td>".&html_escape($pub)."</td>";
    print "<td>".&html_escape($allowed)."</td>";
    print "<td>".&html_escape($endpoint)."</td>";
    print "<td>".&html_escape($hs)."</td>";
    print "<td>".&html_escape($rx)."</td>";
    print "<td>".&html_escape($tx)."</td>";
    print "<td>$action</td>";
    print "</tr>";
}
print "</tbody></table></div>";

if (&can_edit()) {
    print "<br>";
    print &ui_link("peer_create.cgi?iface=".&urlize($iface), $text{'peers_add'});
}

&ui_print_footer("index.cgi", $text{'index_title'});
