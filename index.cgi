#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

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

# Allow selecting Docker container when applicable
if ($in{'docker_container'} && &can_edit()) {
    my $containers = &list_wireguard_containers();
    my %by_id = map { $_->{'id'} => $_ } @$containers;
    &error($text{'container_invalid'}) unless $by_id{$in{'docker_container'}};
    my $chosen = $by_id{$in{'docker_container'}};
    my $store = $chosen->{'name'} || $chosen->{'id'};
    $config{'docker_container_name'} = $store;
    &save_module_config(\%config);
}
&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);

# Configuration form for custom config directory
if (&can_edit() && $in{'save_config'}) {
    if ($in{'config_dir'}) {
        $config{'config_dir'} = $in{'config_dir'};
    }
    if ($in{'docker_container_name'}) {
        $config{'docker_container_name'} = $in{'docker_container_name'};
    }
    if ($in{'backend_type'}) {
        $config{'backend_type'} = $in{'backend_type'};
    }
    if ($in{'docker_config_path'}) {
        $config{'docker_config_path'} = $in{'docker_config_path'};
    }
    &save_module_config(\%config);
    print "<p><b>Configuration saved.</b></p>";
}

my $backend = &detect_backend();
print &ui_subheading("$text{'index_backend'}: $backend->{detail}");

# Config directory form
if (&can_edit()) {
    print &ui_form_start("index.cgi", "post");
    print &ui_hidden("save_config", 1);
    print &ui_table_start("Configuration", undef, 2);
    
    # Backend type selection
    my @backend_opts = (
        ['docker', 'Docker Container (linuxserver/wireguard)'],
        ['host', 'Native Linux Installation (wg-quick)']
    );
    print &ui_table_row("WireGuard Backend:",
        &ui_radio("backend_type", $config{'backend_type'} || 'docker', \@backend_opts));
    
    print &ui_table_row("Docker Container Name:",
        &ui_textbox("docker_container_name", $config{'docker_container_name'} || 'wireguard', 30));
    print &ui_table_row("Config Path Inside Container:",
        &ui_textbox("docker_config_path", $config{'docker_config_path'} || '/config', 30));
    print &ui_table_row("Host Config Directory (for Native):",
        &ui_textbox("config_dir", $config{'config_dir'} || '/etc/wireguard', 50));
    print &ui_table_end();
    print &ui_submit("Save Configuration");
    print &ui_form_end();
    print "<br>";
}
my $containers = &list_wireguard_containers();

if (&can_edit() && $backend->{type} eq 'docker' && @$containers) {
    print &ui_form_start("index.cgi", "post");
    print &ui_table_start($text{'container_select'}, undef, 2);
    my @opts = map { [ $_->{'id'}, ($_->{'name'} ? "$_->{'name'} ($_->{'image'})" : "$_->{'id'} ($_->{'image'})") ] } @$containers;
    my $selected = '';
    foreach my $c (@$containers) {
        if ($config{'docker_container_name'} && ($config{'docker_container_name'} eq $c->{'name'} || $config{'docker_container_name'} eq $c->{'id'})) {
            $selected = $c->{'id'};
            last;
        }
    }
    print &ui_table_row($text{'container_label'},
        &ui_select("docker_container", $selected, \@opts, 1));
    print &ui_table_end();
    print &ui_submit($text{'container_apply'});
    print &ui_form_end();
}

if ($backend->{type} eq 'none') {
    print &ui_table_start($text{'index_diag'}, undef, 2);
    if ($backend->{diag}) {
        foreach my $k (keys %{$backend->{diag}}) {
            print &ui_table_row($k, $backend->{diag}{$k});
        }
    }
    print &ui_table_end();
    if (&can_edit() && @$containers) {
        print &ui_form_start("index.cgi", "post");
        print &ui_table_start($text{'container_select'}, undef, 2);
        my @opts = map { [ $_->{'id'}, ($_->{'name'} ? "$_->{'name'} ($_->{'image'})" : "$_->{'id'} ($_->{'image'})") ] } @$containers;
        print &ui_table_row($text{'container_label'},
            &ui_select("docker_container", undef, \@opts, 1));
        print &ui_table_end();
        print &ui_submit($text{'container_apply'});
        print &ui_form_end();
    }
    &ui_print_footer(undef, $text{'index_title'});
    exit;
}

my @ifaces = &list_interfaces($backend);
if (!@ifaces) {
    print "<p>$text{'config_missing'}</p>";
    &ui_print_footer(undef, $text{'index_title'});
    exit;
}

print &ui_table_start($text{'index_interfaces'}, "width=100%", 4);
print "<tr><th>$text{'index_interfaces'}</th><th>$text{'index_status'}</th><th>$text{'index_peers'}</th><th>$text{'index_actions'}</th></tr>";

foreach my $iface (@ifaces) {
    my $status = '-';
    if ($backend->{type} eq 'host') {
        my $out = &backquote_command("/bin/systemctl is-active wg-quick\@$iface 2>/dev/null");
        $status = ($? == 0) ? 'active' : 'inactive';
    } else {
        my $out = &backquote_command("docker inspect -f '{{.State.Running}}' ".&quote_escape($backend->{container})." 2>/dev/null");
        $status = ($out =~ /true/) ? 'container running' : 'stopped';
    }

    my $path = &get_config_path($backend, $iface);
    my $peer_count = 0;
    if ($backend->{type} eq 'docker') {
        # For Docker, always try reading from inside container first
        my $parsed = &parse_wg_config_docker($backend, $iface);
        if ($parsed) {
            $peer_count = scalar(@{$parsed->{peers}});
        } elsif ($path && -f $path) {
            # Fallback to host file if container read fails
            my $parsed_host = &parse_wg_config($path);
            $peer_count = scalar(@{$parsed_host->{peers}}) if $parsed_host;
        }
    } elsif ($path && -f $path) {
        my $parsed = &parse_wg_config($path);
        $peer_count = scalar(@{$parsed->{peers}}) if $parsed;
    }

    my @links;
    push @links, &ui_link("peers.cgi?iface=".&urlize($iface), $text{'index_manage'});
    push @links, &ui_link("peer_create.cgi?iface=".&urlize($iface), $text{'peers_add'});
    push @links, &ui_link("apply.cgi?iface=".&urlize($iface)."&action=restart", $text{'index_restart'});
    push @links, &ui_link("apply.cgi?iface=".&urlize($iface)."&action=start", $text{'index_start'});
    push @links, &ui_link("apply.cgi?iface=".&urlize($iface)."&action=stop", $text{'index_stop'});

    print &ui_table_row($iface, $status, $peer_count, join(" | ", @links));
}

print &ui_table_end();

# Show peers for each interface
print "<div id='qrModal' style='display:none; position:fixed; z-index:1000; left:0; top:0; width:100%; height:100%; background-color:rgba(0,0,0,0.5);'>";
print "<div style='background-color:white; margin:10% auto; padding:20px; border:1px solid #888; width:320px; text-align:center;'>";
print "<span onclick='closeQR()' style='color:#aaa; float:right; font-size:28px; font-weight:bold; cursor:pointer;'>&times;</span>";
print "<h3 id='qrTitle'>QR Code</h3>";
print "<img id='qrImg' src='' alt='QR Code' style='max-width:260px;'/>";
print "</div></div>";
print "<script>function showQR(url,title){var m=document.getElementById('qrModal');var i=document.getElementById('qrImg');var t=document.getElementById('qrTitle');i.src=url;t.textContent=title||'QR Code';m.style.display='block';} function closeQR(){document.getElementById('qrModal').style.display='none';document.getElementById('qrImg').src='';}</script>";

foreach my $iface (@ifaces) {
    print "<br>";
    print &ui_subheading("Peers for $iface");
    
    if (&can_edit()) {
        print &ui_link("peer_create.cgi?iface=".&urlize($iface), $text{'peers_add'});
        print "<br><br>";
    }

    my $parsed;
    if ($backend->{type} eq 'docker') {
        $parsed = &parse_wg_config_docker($backend, $iface);
    } else {
        my $path = &get_config_path($backend, $iface);
        $parsed = &parse_wg_config($path) if $path && -f $path;
    }
    
    if ($parsed && @{$parsed->{peers}}) {
        my $qr_enabled = $config{'enable_qr'} && &has_command('qrencode');
        print &ui_table_start("Peers", "width=100%", 4);
        print "<tr><th>Name</th><th>Public Key</th><th>Allowed IPs</th><th>Actions</th></tr>";
        
        foreach my $peer (@{$parsed->{peers}}) {
            my $peer_name = $peer->{'Name'} || '';
            my $name = $peer_name || 'Unnamed';
            my $pubkey = substr($peer->{'PublicKey'} || '', 0, 20) . '...';
            my $allowed = $peer->{'AllowedIPs'} || '';
            my @actions;
            if (&can_edit()) {
                push @actions, &ui_link("peer_edit.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($peer->{'PublicKey'}), $text{'peers_edit'});
                push @actions, &ui_link("peer_delete.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($peer->{'PublicKey'}), $text{'peers_delete'});
            }
            my $conf_path = &peer_config_path($iface, $peer->{'PublicKey'});
            if ($conf_path && -f $conf_path) {
                push @actions, &ui_link("peer_download.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($peer->{'PublicKey'})."&name=".&urlize($peer_name), $text{'peers_download'});
                if ($qr_enabled) {
                    my $qr_url = "peer_qr.cgi?iface=".&urlize($iface)."&pubkey=".&urlize($peer->{'PublicKey'})."&name=".&urlize($peer_name)."&raw=1";
                    push @actions, "<a href='#' onclick=\"showQR('$qr_url','QR - ".&html_escape($name)."'); return false;\">$text{'peers_qr'}</a>";
                }
            }
            my $actions = @actions ? join(" | ", @actions) : '-';
            print &ui_table_row($name, $pubkey, $allowed, $actions);
        }
        print &ui_table_end();
    } else {
        print "<p>No peers configured for this interface.</p>";
    }
}
&ui_print_footer(undef, $text{'index_title'});
