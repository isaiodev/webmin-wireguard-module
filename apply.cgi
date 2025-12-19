#!/usr/bin/perl
use strict;
use warnings;

do 'wireguard-lib.pl';
our (%text, %config, %in, %access);
&init_config();
&ReadParse();

my $iface = $in{'iface'};
my $action = $in{'action'} || '';

&error($text{'iface_invalid'}) unless &validate_iface($iface);
&error("Write access required") unless &can_edit();

my $backend = &detect_backend();
&error($text{'backend_none'}) if $backend->{type} eq 'none';

my ($code, $out);
if ($action eq 'start' || $action eq 'stop' || $action eq 'restart') {
    ($code, $out) = &service_action($backend, $iface, $action);
} else {
    ($code, $out) = &apply_changes($backend, $iface);
}

&ui_print_header(undef, $text{'index_apply'}, "", undef, 1, 1);
if ($code == 0) {
    print &ui_subheading("Action $action completed");
} else {
    print &ui_subheading("Action failed (exit $code)");
}
print "<pre>".&html_escape($out)."</pre>" if $out;
print &ui_link("index.cgi", "Back");
&ui_print_footer("index.cgi", $text{'index_title'});
