#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);

my $backend = &detect_backend();
print &ui_subheading("$text{'index_backend'}: $backend->{detail}");

if ($backend->{type} eq 'none') {
    print &ui_table_start($text{'index_diag'}, undef, 2);
    if ($backend->{diag}) {
        foreach my $k (keys %{$backend->{diag}}) {
            print &ui_table_row($k, $backend->{diag}{$k});
        }
    }
    print &ui_table_end();
    &ui_print_footer(undef, $text{'index_title'});
    exit;
}

my @ifaces = &list_interfaces($backend);
if (!@ifaces) {
    print &ui_text($text{'config_missing'});
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
