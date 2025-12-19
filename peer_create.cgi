#!/usr/bin/perl
use strict;
use warnings;
use MIME::Base64 qw(encode_base64 decode_base64);

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

sub _json_escape {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/\\/\\\\/g;
    $s =~ s/"/\\"/g;
    $s =~ s/[\r\n]//g;
    return $s;
}

my $iface = $in{'iface'};
&error($text{'iface_invalid'}) unless &validate_iface($iface);

my $backend = &detect_backend();
&error($text{'backend_none'}) if $backend->{type} eq 'none';
&error("Write access required") unless &can_edit();

# Live stats JSON endpoint for newly created peer
if ($in{'json'} && $in{'watch_pub'}) {
    my $stats = &get_peer_stats($backend, $iface);
    my $entry = $stats->{$in{'watch_pub'}} || {};
    print "Content-type: application/json\n\n";
    if (%$entry) {
        my $hs = _json_escape($entry->{'last_handshake'} || '');
        my $rx = $entry->{'rx'} || 0;
        my $tx = $entry->{'tx'} || 0;
        print qq|{"ok":true,"last_handshake":"$hs","rx":$rx,"tx":$tx}|;
    } else {
        print '{"ok":false}';
    }
    exit;
}

# On-demand download of the generated client config
if ($in{'download_conf'} && $in{'conf_b64'}) {
    my $conf = decode_base64($in{'conf_b64'});
    print "Content-type: text/plain\n";
    print "Content-Disposition: attachment; filename=\"wireguard-$iface.conf\"\n\n";
    print $conf;
    exit;
}

my $path = &get_config_path($backend, $iface);
&error($text{'config_missing'}) unless $path && -f $path;

my $parsed = &parse_wg_config($path);

my @used_ips;
foreach my $p (@{$parsed->{peers}}) {
    if (my $ai = $p->{'AllowedIPs'}) {
        foreach my $entry (split(/\s*,\s*/, $ai)) {
            if ($entry =~ /^([0-9.]+)\/\d+$/) {
                push @used_ips, $1;
            }
        }
    }
}
if (my $int_addr = $parsed->{interface}->{'Address'}) {
    foreach my $entry (split(/\s*,\s*/, $int_addr)) {
        if ($entry =~ /^([0-9.]+)\/\d+$/) {
            push @used_ips, $1;
        }
    }
}
my $pool = $config{'client_pool_cidr'} || '10.0.0.0/24';
my $suggest_ip = &suggest_next_ip($pool, \@used_ips) || '';

if ($in{'save'}) {
    &error($text{'allowedips_invalid'}) unless &validate_allowed_ips($in{'allowedips'});
    my $preshared = $in{'preshared'};
    &error($text{'pubkey_invalid'}) if $preshared && !&validate_key($preshared);
    my $keepalive = $in{'keepalive'};
    &error("Invalid keepalive") if $keepalive && $keepalive !~ /^\d+$/;

    my $client_priv = $in{'client_priv'};
    my $client_pub = $in{'client_pub'};
    if ($client_priv) {
        &error($text{'pubkey_invalid'}) unless &validate_key($client_priv);
    }

    if (!$client_priv) {
        my $gen_cmd = ($backend->{type} eq 'docker')
            ? "docker exec ".&quote_escape($backend->{container})." wg genkey"
            : "/usr/bin/wg genkey";
        $client_priv = &backquote_command("$gen_cmd 2>/dev/null");
        chomp $client_priv;
        &error("Failed to generate private key") if $? != 0 || !$client_priv;
    }

    if (!$client_pub) {
        my $cmd = ($backend->{type} eq 'docker')
            ? "docker exec ".&quote_escape($backend->{container})." /bin/sh -c 'echo ".&quote_escape($client_priv)." | wg pubkey'"
            : "/bin/sh -c 'echo ".&quote_escape($client_priv)." | /usr/bin/wg pubkey'";
        $client_pub = &backquote_command("$cmd 2>/dev/null");
        chomp $client_pub;
        &error("Failed to derive public key") if $? != 0 || !$client_pub;
    }

    my @block;
    push @block, "[Peer]";
    if ($in{'name'}) {
        my $name = $in{'name'};
        $name =~ s/[\r\n]//g;
        push @block, "# Name: $name";
    }
    push @block, "PublicKey = $client_pub";
    push @block, "AllowedIPs = ".$in{'allowedips'};
    push @block, "PresharedKey = $preshared" if $preshared;
    push @block, "PersistentKeepalive = $keepalive" if $keepalive;

    &add_peer_block($path, \@block);

    # Build client config
    my $server_pub = '';
    if (my $int_priv = $parsed->{interface}->{'PrivateKey'}) {
        my $cmd = "/bin/sh -c 'echo ".&quote_escape($int_priv)." | /usr/bin/wg pubkey'";
        $server_pub = &backquote_command("$cmd 2>/dev/null");
        chomp $server_pub;
    }
    my $endpoint = $config{'default_endpoint'} || '';
    my $dns = $config{'default_dns'} || '';
    my $client_allowed = $config{'default_client_allowed_ips'} || '0.0.0.0/0';

    my @client;
    push @client, "[Interface]";
    push @client, "PrivateKey = $client_priv";
    push @client, "Address = ".$in{'allowedips'};
    push @client, "DNS = $dns" if $dns;
    push @client, "";
    push @client, "[Peer]";
    push @client, "PublicKey = $server_pub" if $server_pub;
    push @client, "AllowedIPs = $client_allowed";
    push @client, "Endpoint = $endpoint" if $endpoint;
    push @client, "PersistentKeepalive = $keepalive" if $keepalive;

    my $client_conf = join("\n", @client)."\n";
    my $conf_b64 = encode_base64($client_conf, "");

    &ui_print_header(undef, $text{'peer_create_title'}, "", undef, 1, 1);
    print &ui_subheading($text{'peer_added'});
    print &ui_table_start($text{'client_conf_label'}, undef, 1);
    print &ui_table_row($text{'config_label'}, "<pre>".&html_escape($client_conf)."</pre>");
    print &ui_table_row($text{'download_conf'},
        &ui_form_start("peer_create.cgi", "post").
        &ui_hidden("iface", $iface).
        &ui_hidden("download_conf", 1).
        &ui_hidden("conf_b64", $conf_b64).
        &ui_submit($text{'download_conf'}).
        &ui_form_end()
    );
    if ($config{'enable_qr'} && &has_command('qrencode')) {
        my $qr = &backquote_command("echo ".&quote_escape($client_conf)." | qrencode -t ASCII 2>/dev/null");
        if ($qr) {
            print &ui_table_row($text{'qr_label'}, "<pre>".&html_escape($qr)."</pre>");
        }
    }
    print &ui_table_end();

    # Live stats block for the new peer
    my $live_stats = &get_peer_stats($backend, $iface);
    my $entry = $live_stats->{$client_pub} || {};
    my $hs = $entry->{'last_handshake'} || $text{'stats_waiting'};
    my $rx = $entry->{'rx'} || 0;
    my $tx = $entry->{'tx'} || 0;
    print &ui_table_start($text{'live_stats'}, undef, 2);
    print &ui_table_row($text{'peers_last_handshake'}, "<span id='wg-hs'>".&html_escape($hs)."</span>");
    print &ui_table_row($text{'stats_rx'}, "<span id='wg-rx'>".&html_escape($rx)."</span>");
    print &ui_table_row($text{'stats_tx'}, "<span id='wg-tx'>".&html_escape($tx)."</span>");
    print &ui_table_end();
    print "<div><em>$text{'stats_refresh_note'}</em></div>";
    print "<script>
    (function(){
        var pub = ".&to_json_text($client_pub).";
        var iface = ".&to_json_text($iface).";
        async function refresh() {
            try {
                var r = await fetch('peer_create.cgi?iface=' + encodeURIComponent(iface) + '&watch_pub=' + encodeURIComponent(pub) + '&json=1');
                if (!r.ok) return;
                var data = await r.json();
                if (!data || !data.ok) return;
                document.getElementById('wg-hs').textContent = data.last_handshake || '$text{'stats_waiting'}';
                document.getElementById('wg-rx').textContent = data.rx || '0';
                document.getElementById('wg-tx').textContent = data.tx || '0';
            } catch (e) { }
        }
        refresh();
        setInterval(refresh, 5000);
    })();
    </script>";

    print &ui_link("peers.cgi?iface=".&urlize($iface), "Back to peers");
    &ui_print_footer("index.cgi", $text{'index_title'});
    exit;
}

&ui_print_header(undef, $text{'peer_create_title'}, "", undef, 1, 1);
print &ui_subheading("$text{'peers_title'} $iface");

print &ui_form_start("peer_create.cgi", "post");
print &ui_hidden("iface", $iface);
print &ui_table_start($text{'peer_create_title'}, undef, 2);
print &ui_table_row($text{'peers_name'},
    &ui_textbox("name", "", 40));
print &ui_table_row($text{'peers_allowedips'},
    &ui_textbox("allowedips", $suggest_ip, 30)." (pool $pool)");
print &ui_table_row("Client private key",
    &ui_textbox("client_priv", "", 45)." (optional, generated if empty)");
print &ui_table_row("Preshared key",
    &ui_textbox("preshared", "", 45)." (optional)");
print &ui_table_row("Persistent keepalive",
    &ui_textbox("keepalive", "25", 5)." seconds (optional)");
print &ui_table_end();
print &ui_submit($text{'peers_add'}, "save");
print &ui_form_end();
&ui_print_footer("index.cgi", $text{'index_title'});
