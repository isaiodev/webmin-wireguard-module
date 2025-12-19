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

    &ui_print_header(undef, $text{'peer_create_title'}, "", undef, 1, 1);
    print &ui_subheading($text{'peer_added'});
    print &ui_table_start("Client configuration", undef, 1);
    print &ui_table_row("Config", "<pre>".&html_escape($client_conf)."</pre>");
    if ($config{'enable_qr'} && &has_command('qrencode')) {
        my $qr = &backquote_command("echo ".&quote_escape($client_conf)." | qrencode -t ASCII 2>/dev/null");
        if ($qr) {
            print &ui_table_row("QR", "<pre>".&html_escape($qr)."</pre>");
        }
    }
    print &ui_table_end();
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
print &ui_submit($text{'peers_add'});
print &ui_form_end();
&ui_print_footer("index.cgi", $text{'index_title'});
