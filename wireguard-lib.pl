#!/usr/bin/perl
use strict;
use warnings;

our (%text, %config, %access, %in);
BEGIN { push(@INC, ".."); }
use WebminCore;
&init_config();
&textdomain('wireguard');

use File::Copy qw(copy);
use File::Temp qw(tempfile);
use POSIX qw(strftime);
use Socket;

our $DEFAULT_MODE = 0600;

# Validate an interface name
sub validate_iface {
    my ($iface) = @_;
    return $iface && $iface =~ /^[A-Za-z0-9_.-]+$/;
}

# Validate a base64-like key (WireGuard keys)
sub validate_key {
    my ($key) = @_;
    return 0 unless defined $key;
    return $key =~ m{^[A-Za-z0-9+/=]{32,64}$};
}

# Validate a CIDR list (comma-separated)
sub validate_allowed_ips {
    my ($ips) = @_;
    return 0 unless defined $ips;
    foreach my $entry (split(/\s*,\s*/, $ips)) {
        next if $entry eq '';
        return 0 unless $entry =~ m{^([0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?$};
    }
    return 1;
}

# Utility to run a command safely
sub safe_cmd {
    my ($cmd_ar) = @_;
    my $out = &backquote_command(join(' ', map { &quote_escape($_) } @$cmd_ar));
    my $code = $?;
    return wantarray ? ($code, $out) : $out;
}

sub can_edit {
    return !$access{'readonly'};
}

sub urlize {
    my ($str) = @_;
    $str =~ s/([^A-Za-z0-9_.-])/sprintf("%%%02X", ord($1))/ge;
    return $str;
}

sub has_command_in_path {
    my ($cmd) = @_;
    return 0 unless $cmd;
    # Check if it's an absolute path
    return -x $cmd if $cmd =~ m{^/};
    # Search in PATH
    foreach my $dir (split(/:/, $ENV{'PATH'} || '')) {
        return 1 if -x "$dir/$cmd";
    }
    return 0;
}

sub has_command {
    my ($cmd) = @_;
    return &has_command_in_path($cmd);
}

# Backend detection
sub detect_backend {
    my %diag;
    my $cfg_dir = $config{'config_dir'} || '/etc/wireguard';
    my $wg_path = '/usr/bin/wg';
    my $systemctl = &has_command_in_path('systemctl') || -x '/bin/systemctl';

    # Check for Docker first if container name is specified
    if ($config{'docker_container_name'}) {
        my $docker = &has_command_in_path('docker') || &has_command_in_path('/usr/bin/docker');
        if ($docker) {
            my $container = $config{'docker_container_name'};
            my $running = &backquote_command("docker inspect -f '{{.State.Running}}' ".&quote_escape($container)." 2>/dev/null");
            if ($? == 0) {
                my $status = ($running =~ /true/) ? 'running' : 'stopped';
                return {
                    type       => 'docker',
                    container  => $container,
                    config_dir => $cfg_dir,
                    detail     => "docker ($container - $status)",
                };
            }
        }
    }

    # Try host mode if WireGuard tools are available
    my $host_ok = (-x $wg_path) && (-d $cfg_dir) && $systemctl;
    if ($host_ok) {
        my $unit_exists = (-f '/lib/systemd/system/wg-quick@.service')
            || (-f '/etc/systemd/system/wg-quick@.service');
        if (!$unit_exists && $systemctl) {
            my $out = &backquote_command("systemctl list-unit-files 2>/dev/null");
            $unit_exists = ($out =~ /wg-quick\@/);
        }
        if ($unit_exists) {
            return {
                type       => 'host',
                config_dir => $cfg_dir,
                detail     => "host (wg + wg-quick)",
            };
        }
    }

    # Fallback to any existing config directory (assume Docker)
    if (-d $cfg_dir) {
        return {
            type       => 'docker',
            container  => $config{'docker_container_name'} || 'wireguard',
            config_dir => $cfg_dir,
            detail     => "docker (config dir: $cfg_dir)",
        };
    }

    # Auto-detect Docker containers
    my $docker = &has_command_in_path('docker') || &has_command_in_path('/usr/bin/docker');
    if ($docker) {
        my $info_out = &backquote_command("docker info 2>&1");
        if ($? == 0) {
            my $list = &list_wireguard_containers();
            if (@$list) {
                my $container = $list->[0]->{'name'} || $list->[0]->{'id'};
                my $running = &backquote_command("docker inspect -f '{{.State.Running}}' ".&quote_escape($container)." 2>/dev/null");
                my $status = ($running =~ /true/) ? 'running' : 'stopped';
                return {
                    type       => 'docker',
                    container  => $container,
                    config_dir => $cfg_dir,
                    detail     => "docker ($container - $status)",
                };
            } else {
                $diag{'docker'} = 'No WireGuard container detected.';
            }
        } else {
            $diag{'docker'} = 'Docker daemon unreachable.';
        }
    } else {
        $diag{'docker'} = 'Docker not found in PATH.';
    }

    return {
        type => 'none',
        detail => 'No usable backend detected',
        diag => \%diag,
    };
}

# Enumerate WireGuard-like containers
sub list_wireguard_containers {
    my @out;
    return \@out unless &has_command_in_path('docker') || &has_command_in_path('/usr/bin/docker');
    my $ps = &backquote_command("docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Labels}}' 2>/dev/null");
    return \@out if $? != 0;
    foreach my $line (split(/\n/, $ps)) {
        my ($id, $name, $img, $labels) = split(/\s+/, $line, 4);
        # Look for linuxserver/wireguard or any wireguard-related containers
        next unless ($img && ($img =~ /wireguard/i || $img =~ /linuxserver\/wireguard/i)) || ($labels && $labels =~ /wireguard/i);
        push @out, {
            id     => $id,
            name   => $name,
            image  => $img,
            labels => $labels,
        };
    }
    return \@out;
}

# List interface config files for a backend
sub list_interfaces {
    my ($backend) = @_;
    my @ifs;
    if ($backend->{type} eq 'host') {
        my $dir = $backend->{config_dir};
        return () unless $dir && -d $dir;
        opendir(my $dh, $dir) or return ();
        while (my $f = readdir($dh)) {
            next unless $f =~ /^([A-Za-z0-9_.-]+)\.conf$/;
            push @ifs, $1;
        }
        closedir $dh;
    } elsif ($backend->{type} eq 'docker') {
        # First try host-mounted directory
        if ($backend->{config_dir} && -d $backend->{config_dir}) {
            opendir(my $dh, $backend->{config_dir}) or return ();
            while (my $f = readdir($dh)) {
                next unless $f =~ /^([A-Za-z0-9_.-]+)\.conf$/;
                push @ifs, $1;
            }
            closedir $dh;
        } else {
            # Fallback: read from inside container
            my $out = &backquote_command("docker exec ".&quote_escape($backend->{container})." ls /config 2>/dev/null");
            foreach my $line (split(/\n/, $out)) {
                next unless $line =~ /^([A-Za-z0-9_.-]+)\.conf$/;
                push @ifs, $1;
            }
        }
    }
    return @ifs;
}

# Read a WireGuard config file into structured hash
sub parse_wg_config {
    my ($path) = @_;
    return undef unless $path && -f $path;
    my $lines = &read_file_lines($path);
    my %iface;
    my @peers;
    my $current;
    my $in_peer = 0;
    foreach my $line (@$lines) {
        if ($line =~ /^\s*\[Interface\]/i) {
            $in_peer = 0;
            next;
        }
        if ($line =~ /^\s*\[Peer\]/i) {
            $in_peer = 1;
            $current = {};
            push @peers, $current;
            next;
        }
        if ($in_peer && $line =~ /^\s*#\s*Name:\s*(.+)$/i) {
            $current->{'Name'} = $1;
            next;
        }
        my ($k, $v) = $line =~ /^\s*([^=#]+?)\s*=\s*(.+)$/;
        next unless defined $k;
        $k =~ s/\s+$//;
        if ($in_peer) {
            $current->{$k} = $v;
        } else {
            $iface{$k} = $v;
        }
        if ($in_peer && $line =~ /^\s*#\s*Name:\s*(.+)$/i) {
            $current->{'Name'} = $1;
        }
    }
    return { interface => \%iface, peers => \@peers, lines => $lines };
}

# Read config from Docker container if needed
sub parse_wg_config_docker {
    my ($backend, $iface) = @_;
    return undef unless $backend->{type} eq 'docker' && $iface;
    
    my $out = &backquote_command("docker exec ".&quote_escape($backend->{container})." cat /config/$iface.conf 2>/dev/null");
    return undef if $? != 0 || !$out;
    
    my @lines = split(/\n/, $out);
    my %iface_data;
    my @peers;
    my $current;
    my $in_peer = 0;
    
    foreach my $line (@lines) {
        if ($line =~ /^\s*\[Interface\]/i) {
            $in_peer = 0;
            next;
        }
        if ($line =~ /^\s*\[Peer\]/i) {
            $in_peer = 1;
            $current = {};
            push @peers, $current;
            next;
        }
        if ($in_peer && $line =~ /^\s*#\s*Name:\s*(.+)$/i) {
            $current->{'Name'} = $1;
            next;
        }
        my ($k, $v) = $line =~ /^\s*([^=#]+?)\s*=\s*(.+)$/;
        next unless defined $k;
        $k =~ s/\s+$//;
        if ($in_peer) {
            $current->{$k} = $v;
        } else {
            $iface_data{$k} = $v;
        }
    }
    return { interface => \%iface_data, peers => \@peers, lines => \@lines };
}

# Backup a configuration file
sub backup_file {
    my ($path) = @_;
    return 0 unless $path && -f $path;
    my $ts = time();
    my $dst = "$path.bak.$ts";
    copy($path, $dst);
    chmod $DEFAULT_MODE, $dst;
    if (my $retention = $config{'backup_retention'} || 10) {
        my @backups = sort { $b cmp $a } glob("$path.bak.*");
        my $i = 0;
        foreach my $b (@backups) {
            $i++;
            next if $i <= $retention;
            unlink $b;
        }
    }
    return 1;
}

sub ensure_permissions {
    my ($path) = @_;
    return unless $path && -e $path;
    chmod $DEFAULT_MODE, $path;
}

# Save updated config lines
sub save_config_lines {
    my ($path, $lines) = @_;
    &backup_file($path);
    &write_file_lines($path, $lines);
    &ensure_permissions($path);
    &flush_file_lines($path);
}

# Next available /32 from pool
sub suggest_next_ip {
    my ($pool, $used_ref) = @_;
    my %used = map { $_ => 1 } @$used_ref;
    return undef unless $pool && $pool =~ m{^([0-9]{1,3}(?:\.[0-9]{1,3}){3})/(\d{1,2})$};
    my ($base, $mask) = ($1, $2);
    return undef if $mask > 32;
    my $net = unpack("N", inet_aton($base));
    my $hosts = 2 ** (32 - $mask);
    for (my $i = 1; $i < $hosts-1; $i++) {
        my $addr = inet_ntoa(pack("N", $net + $i));
        next if $used{$addr};
        return "$addr/32";
    }
    return undef;
}

# Get peer stats via wg show dump
sub get_peer_stats {
    my ($backend, $iface) = @_;
    return {} unless $backend->{type} && $iface;
    my @cmd;
    if ($backend->{type} eq 'host') {
        @cmd = ('/usr/bin/wg', 'show', $iface, 'dump');
    } elsif ($backend->{type} eq 'docker') {
        @cmd = ('docker', 'exec', $backend->{container}, 'wg', 'show', $iface, 'dump');
    } else { return {}; }
    my ($code, $out) = &safe_cmd(\@cmd);
    return {} if $code != 0 || !$out;
    my %stats;
    foreach my $line (split(/\n/, $out)) {
        my @c = split(/\t/, $line);
        next if $c[0] && $c[0] eq 'interface';
        next unless @c >= 8;
        $stats{$c[1]} = {
            endpoint => $c[3],
            allowed_ips => $c[4],
            last_handshake => $c[5],
            rx => $c[6],
            tx => $c[7],
        };
    }
    return \%stats;
}

sub get_config_path {
    my ($backend, $iface) = @_;
    return undef unless $backend && $iface;
    if ($backend->{type} eq 'host') {
        return "$backend->{config_dir}/$iface.conf";
    } elsif ($backend->{type} eq 'docker' && $backend->{config_dir}) {
        return "$backend->{config_dir}/$iface.conf";
    }
    return undef;
}

sub apply_changes {
    my ($backend, $iface) = @_;
    return (1, $text{'apply_none'}) if $backend->{type} eq 'none';
    if ($backend->{type} eq 'host') {
        return safe_cmd(['/bin/systemctl','restart',"wg-quick\@$iface"]);
    } else {
        # For Docker, restart the interface inside the container
        my ($code, $out) = safe_cmd(['docker','exec',$backend->{container},'wg-quick','down',$iface]);
        my ($code2, $out2) = safe_cmd(['docker','exec',$backend->{container},'wg-quick','up',$iface]);
        return ($code2, "$out\n$out2");
    }
}

sub service_action {
    my ($backend, $iface, $action) = @_;
    return (1, "No backend available") if $backend->{type} eq 'none';
    
    if ($backend->{type} eq 'host') {
        if ($action eq 'start') {
            return safe_cmd(['/bin/systemctl','start',"wg-quick\@$iface"]);
        } elsif ($action eq 'stop') {
            return safe_cmd(['/bin/systemctl','stop',"wg-quick\@$iface"]);
        } elsif ($action eq 'restart') {
            return safe_cmd(['/bin/systemctl','restart',"wg-quick\@$iface"]);
        }
    } else {
        # Docker actions
        if ($action eq 'start') {
            return safe_cmd(['docker','exec',$backend->{container},'wg-quick','up',$iface]);
        } elsif ($action eq 'stop') {
            return safe_cmd(['docker','exec',$backend->{container},'wg-quick','down',$iface]);
        } elsif ($action eq 'restart') {
            my ($code, $out) = safe_cmd(['docker','exec',$backend->{container},'wg-quick','down',$iface]);
            my ($code2, $out2) = safe_cmd(['docker','exec',$backend->{container},'wg-quick','up',$iface]);
            return ($code2, "$out\n$out2");
        }
    }
    return (1, "Unknown action: $action");
}

1;e} eq 'none';
    if ($backend->{type} eq 'host') {
        return safe_cmd(['/bin/systemctl','restart',"wg-quick\@$iface"]);
    } else {
        return safe_cmd(['docker','restart',$backend->{container}]);
    }
}

sub service_action {
    my ($backend, $iface, $action) = @_;
    if ($backend->{type} eq 'host') {
        return safe_cmd(['/bin/systemctl',$action,"wg-quick\@$iface"]);
    } elsif ($backend->{type} eq 'docker') {
        return safe_cmd(['docker',$action,$backend->{container}]);
    }
    return (1, "No backend");
}

sub get_config_path {
    my ($backend, $iface) = @_;
    return undef unless validate_iface($iface);
    my $dir = $backend->{config_dir} || '/etc/wireguard';
    return "$dir/$iface.conf";
}

# Create a new peer block
sub add_peer_block {
    my ($path, $peer_lines) = @_;
    my $lines = &read_file_lines($path);
    push @$lines, '';
    push @$lines, @$peer_lines;
    &save_config_lines($path, $lines);
}

# Delete peer by public key
sub delete_peer_block {
    my ($path, $pubkey) = @_;
    my $lines = &read_file_lines($path);
    my @out;
    my @buffer;
    my $match = 0;
    foreach my $line (@$lines) {
        if ($line =~ /^\s*\[Peer\]/i) {
            if (@buffer && !$match) {
                push @out, @buffer;
            }
            @buffer = ($line);
            $match = 0;
            next;
        }
        if (@buffer) {
            if ($line =~ /^\s*PublicKey\s*=\s*(.+)$/i) {
                $match = 1 if $1 eq $pubkey;
            }
            push @buffer, $line;
        } else {
            push @out, $line;
        }
    }
    if (@buffer && !$match) {
        push @out, @buffer;
    }
    &save_config_lines($path, \@out);
}

sub can_edit {
    return !$access{'nowrite'};
}

1;
