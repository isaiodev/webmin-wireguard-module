#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

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
        &save_module_config(\%config);
        print "<p><b>Configuration saved. Config directory set to: $in{'config_dir'}</b></p>";
    }
}

my $backend = &detect_backend();
print &ui_subheading("$text{'index_backend'}: $backend->{detail}");

# Config directory form
if (&can_edit()) {
    print &ui_form_start("index.cgi", "post");
    print &ui_hidden("save_config", 1);
    print &ui_table_start("Configuration", undef, 2);
    print &ui_table_row("WireGuard Config Directory:",
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

print &ui_table_start($text{'index_interfaces'}, "width=100%", 5);
print &ui_table_header([ $text{'index_interfaces'}, $text{'index_status'},
    $text{'index_peers'}, $text{'index_actions'} ]);

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
    if ($path && -f $path) {
        my $parsed = &parse_wg_config($path);
        $peer_count = scalar(@{$parsed->{peers}}) if $parsed;
    }

    my @links;
    push @links, &ui_link("peers.cgi?iface=".&urlize($iface), $text{'index_manage'});
    if (&can_edit()) {
        push @links, &ui_link("apply.cgi?iface=".&urlize($iface)."&action=restart", $text{'index_apply'});
        push @links, &ui_link("apply.cgi?iface=".&urlize($iface)."&action=start", $text{'index_start'});
        push @links, &ui_link("apply.cgi?iface=".&urlize($iface)."&action=stop", $text{'index_stop'});
    }

    print &ui_table_row($iface, $status, $peer_count, join(" | ", @links));
}

print &ui_table_end();
&ui_print_footer(undef, $text{'index_title'});
