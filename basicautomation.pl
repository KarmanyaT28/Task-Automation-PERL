#!/usr/bin/perl

use strict;
use warnings;
use File::Find;
use File::Copy;
use Sys::Syslog qw(:standard :macros);

# File Management Task: Find and copy suspicious files to a secure directory
sub copy_suspicious_files {
    my $source_dir = "/var/log";  # Example directory to search for suspicious files
    my $target_dir = "/secure_storage/suspicious_files";

    find(sub {
        if (-f $_ && -s _ > 1000000) {  # Example condition: File size > 1MB
            syslog(LOG_INFO, "Copying suspicious file $_ to $target_dir");
            copy($_, $target_dir) or syslog(LOG_ERR, "Failed to copy $_: $!");
        }
    }, $source_dir);
}

# System Monitoring Task: Check for unauthorized SSH login attempts
sub monitor_ssh_logs {
    my $ssh_log = "/var/log/auth.log";  # Example SSH log file
    my $num_attempts = 0;

    open(my $fh, '<', $ssh_log) or die "Cannot open $ssh_log: $!";
    while (my $line = <$fh>) {
        if ($line =~ /Failed password/i) {
            $num_attempts++;
        }
    }
    close($fh);

    if ($num_attempts > 5) {
        syslog(LOG_WARNING, "Multiple failed SSH login attempts detected: $num_attempts");
    }
}

# Log Analysis Task: Analyze syslog for potential security issues
sub analyze_syslog {
    my $syslog_file = "/var/log/syslog";  # Example syslog file

    open(my $fh, '<', $syslog_file) or die "Cannot open $syslog_file: $!";
    while (my $line = <$fh>) {
        if ($line =~ /error/i || $line =~ /warning/i) {
            syslog(LOG_WARNING, "Potential security issue detected in syslog: $line");
        }
    }
    close($fh);
}

# Main script execution
openlog("security_analyzer", "ndelay,pid", "local0");

copy_suspicious_files();
monitor_ssh_logs();
analyze_syslog();

closelog();
