#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

my $iface = $in{'iface'};
&error($text{'iface_invalid'}) unless &validate_iface($iface);

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

    if ($backend->{type} eq 'docker') {
        my $lines = $parsed->{lines} || [];
        my $out = &append_peer_lines($lines, \@block);
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
        &add_peer_block($path, \@block);
    }

    # Build and save client config
    my $server_pub = '';
    if (my $int_priv = $parsed->{interface}->{'PrivateKey'}) {
        my $cmd = "/bin/sh -c 'echo ".&quote_escape($int_priv)." | /usr/bin/wg pubkey'";
        $server_pub = &backquote_command("$cmd 2>/dev/null");
        chomp $server_pub;
    }

    my $listen_port = $parsed->{interface}->{'ListenPort'} || '51820';
    my $host = &get_my_address();
    my %server_data = (
        'PublicKey' => $server_pub,
        'Endpoint'  => $config{'default_endpoint'} || "$host:$listen_port",
    );
    my %peer_data = (
        'PrivateKey'   => $client_priv,
        'PublicKey'    => $client_pub,
        'AllowedIPs'   => $in{'allowedips'},
        'PresharedKey' => $preshared,
        'DNS'          => $config{'default_dns'} || '',
    );

    if (!&create_peer_config_file($iface, \%peer_data, \%server_data)) {
        &error($text{'peer_config_write_failed'});
    }

    my $client_conf_path = &get_peer_config_path($iface, $client_pub);
    my $client_conf = &read_file_contents($client_conf_path);

    &ui_print_header(undef, $text{'peer_create_title'}, "", undef, 1, 1);
    print &ui_subheading("$text{'peer_create_title'} - Step 2 of 2");
    print &ui_table_start("Client configuration", undef, 1);
    print &ui_table_row("Config", "<pre>".&html_escape($client_conf)."</pre>");
    
    # QR Code generation
    if ($config{'enable_qr'} && &has_command('qrencode')) {
        my $qr_cmd = "echo ".&quote_escape($client_conf)." | qrencode -t PNG -o - | base64 -w 0";
        my $qr_base64 = &backquote_command("$qr_cmd 2>/dev/null");
        if ($qr_base64 && $? == 0) {
            chomp $qr_base64;
            print &ui_table_row("QR Code", 
                "<button onclick='showQR()' type='button'>Show QR Code</button>".  
                "<div id='qrModal' style='display:none; position:fixed; z-index:1000; left:0; top:0; width:100%; height:100%; background-color:rgba(0,0,0,0.5);'>".
                "<div style='background-color:white; margin:15% auto; padding:20px; border:1px solid #888; width:300px; text-align:center;'>".
                "<span onclick='closeQR()' style='color:#aaa; float:right; font-size:28px; font-weight:bold; cursor:pointer;'>&times;</span>".
                "<h3>QR Code for WireGuard Config</h3>".
                "<img src='data:image/png;base64,$qr_base64' alt='QR Code' style='max-width:250px;'/>".
                "</div></div>".
                "<script>function showQR(){document.getElementById('qrModal').style.display='block';} function closeQR(){document.getElementById('qrModal').style.display='none';}</script>");
        }
    }
    print &ui_table_end();
    if ($client_conf_path && -f $client_conf_path) {
        print "<br>";
        print &ui_link("peer_download.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($client_pub)."&name=".&urlize($in{'name'} || ''), $text{'peers_download'});
    }
    print "<br>";
    print &ui_link("peer_create.cgi?iface=".&urlize($iface), "Add another peer");
    print " | ";
    print &ui_link("peers.cgi?iface=".&urlize($iface), $text{'peers_back'});
    &ui_print_footer("index.cgi", $text{'index_title'});
    exit;
}

&ui_print_header(undef, $text{'peer_create_title'}, "", undef, 1, 1);
print &ui_subheading("$text{'peer_create_title'} - Step 1 of 2");
print "<p>Enter peer details, then review and download the client configuration.</p>";

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
