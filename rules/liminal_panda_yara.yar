#YARA — characteristic file paths
rule LiminalPanda_FilePaths {
  meta:
    author = "Abrar Malik"
    description = "Detects LIMINAL PANDA file paths"
  strings:
    $path1 = "/usr/bin/pingg"
    $path2 = "/usr/lib/om_proc"
    $path3 = "/usr/lib/sgsnemu"
    $path4 = "/usr/lib/tshd"
    $path5 = "/usr/local/sbin/iptables"
    $path6 = "usr/lib/javacee"
  condition:
    2 of them
}

#YARA — C2 domain.
rule LiminalPanda_C2 {
  meta:
    author = "Abrar Malik"
    description = "Detects C2 domain"
  strings:
    $domain = "wuxiapingg.ga"
  condition:
    $domain
}

#YARA — toolkit strings.
rule LIMINAL_PANDA_Toolkit_Detect {
  meta:
    author = "Abrar Malik"
    description = "Detect LIMINAL PANDA tools"
  strings:
    $s1 = "libcord.so"
    $s2 = "vmware-daemon.py"
    $s3 = "pam_unix.so"
    $s4 = "exploit_userspec.py"
  condition:
    2 of them
}
#YARA — PingPong persistence.
rule LiminalPanda_PingPong {
  meta:
    author = "Abrar Malik"
    description = "Detects PingPong backdoor persistence"
  strings:
    $file   = "/usr/bin/pingg"
    $string = "nohup ./pingg >/dev/null 2>&1 &"
    $path   = "/etc/rc.d/init.d/sshd"
  condition:
    2 of them
}
