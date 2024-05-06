#!/usr/bin/perl

use strict;
use warnings;
use threads;
use Thread::Queue;
use File::Find;
use File::Copy;
use Sys::Syslog qw(:standard :macros);

# Global variables
my $suspicious_files_dir = "/secure_storage/suspicious_files";
my $ssh_log = "/var/log/auth.log";
my $syslog_file = "/var/log/syslog";
my $network_log = "/var/log/network.log";
my $file_queue = Thread::Queue->new;

# File Management Task: Find and copy suspicious files to a secure directory
sub copy_suspicious_files {
    my $source_dir = "/var/log";  # Example directory to search for suspicious files

    find(sub {
        if (-f $_ && -s _ > 1000000) {  # Example condition: File size > 1MB
            $file_queue->enqueue($_);
        }
    }, $source_dir);

    while (my $file = $file_queue->dequeue_nb()) {
        syslog(LOG_INFO, "Copying suspicious file $file to $suspicious_files_dir");
        copy($file, $suspicious_files_dir) or syslog(LOG_ERR, "Failed to copy $file: $!");
    }
}

# System Monitoring Task: Check for unauthorized SSH login attempts
sub monitor_ssh_logs {
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
    open(my $fh, '<', $syslog_file) or die "Cannot open $syslog_file: $!";
    while (my $line = <$fh>) {
        if ($line =~ /(error|warning|alert|critical|fail|denied)/i) {
            syslog(LOG_WARNING, "Potential security issue detected in syslog: $line");
        }
    }
    close($fh);
}

# Network Activity Monitoring Task: Monitor network logs for suspicious activity
sub monitor_network_activity {
    open(my $fh, '<', $network_log) or die "Cannot open $network_log: $!";
    while (my $line = <$fh>) {
        if ($line =~ /(attack|intrusion|suspicious|malicious)/i) {
            syslog(LOG_WARNING, "Suspicious network activity detected: $line");
        }
    }
    close($fh);
}

# File Integrity Monitoring Task: Check for unauthorized changes in critical files
sub check_file_integrity {
    my @critical_files = ("/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config");

    foreach my $file (@critical_files) {
        my $md5sum_old = `md5sum $file`;
        sleep(10);  # Wait for 10 seconds to simulate real-time monitoring
        my $md5sum_new = `md5sum $file`;

        if ($md5sum_old ne $md5sum_new) {
            syslog(LOG_WARNING, "File integrity violation detected: $file has been modified");
        }
    }
}

# Main script execution
openlog("security_analyzer", "ndelay,pid", "local0");

my @threads = (
    threads->create(\&copy_suspicious_files),
    threads->create(\&monitor_ssh_logs),
    threads->create(\&analyze_syslog),
    threads->create(\&monitor_network_activity),
    threads->create(\&check_file_integrity)
);

foreach my $thread (@threads) {
    $thread->join();
}

closelog();
