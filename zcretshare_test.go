/*
   Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
   Copyrights licensed under the BSD 3-Clause License. See the
   accompanying LICENSE.txt file for terms.
*/
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func contains(s []string, key string) string {
	for _, a := range s {
		if strings.HasPrefix(a, key) {
			return a
		}
	}
	return ""
}

var dir = "/tmp/"
var infile = "super-secret-test"
var infilePath = "test/"

var send_prikey = "test/id_rsa_test"
var send_pubkey = "test/id_rsa_test.pub"

var recv_prikey = "test/id_ecdsa_test"
var recv_pubkey = "test/id_ecdsa_test.pub"

func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		usr, err := user.Current()
		if err != nil {
			log.Fatalf("zcretshare windows user.current() call failed: %v\n", err)
		}

		dir = usr.HomeDir + "\\"
		infilePath = "test\\"
		send_prikey = "test\\id_rsa_test"
		send_pubkey = "test\\id_rsa_test.pub"

		recv_prikey = "test\\id_ecdsa_test"
		recv_pubkey = "test\\id_ecdsa_test.pub"
	}
	retCode := m.Run()
	os.Exit(retCode)
}

func TestSanity(t *testing.T) {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	fmt.Fprintln(os.Stderr, "CWD: ", exPath)

	var actual []string
	var expected []string

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		args := []string{"receive", "-listen", "127.0.0.1:15432", "-key", recv_prikey, "-sender-pubkey", send_pubkey, "-overwrite", "-dir", dir}
		cmd := exec.Command("./zcretshare", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("ACTUAL: %v\n", actual)
			fmt.Printf("EXPECTED: %v\n", expected)
			t.Fatalf("zcretshare receive returned no-zero error: %v\n", err)
		}
		actual = strings.Split(string(output), "\n")
	}()

	time.Sleep(3000 * time.Millisecond)
	args := []string{"send", "-connect", "ssh://127.0.0.1:15432", "-key", send_prikey, "-receiver-pubkey", recv_pubkey, "-in-file", infilePath + infile}
	cmd := exec.Command("./zcretshare", args...)
	output, err := cmd.CombinedOutput()

	wg.Wait()

	expected = strings.Split(string(output), "\n")

	if err != nil {
		fmt.Printf("ACTUAL: %v\n", actual)
		fmt.Printf("EXPECTED: %v\n", expected)
		t.Fatalf("zcretshare send returned no-zero error: %v\n", err)
	}

	verify(t, actual, expected)
}

func TestSanity2(t *testing.T) {

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	fmt.Fprintln(os.Stderr, "CWD: ", exPath)

	var actual []string
	var expected []string

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		args := []string{"send", "-listen", "127.0.0.1:15432", "-key", send_prikey, "-receiver-pubkey", recv_pubkey, "-in-file", infilePath + infile}
		cmd := exec.Command("./zcretshare", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("ACTUAL: %v\n", actual)
			fmt.Printf("EXPECTED: %v\n", expected)
			t.Fatalf("zcretshare receive returned no-zero error: %v\n", err)
		}
		expected = strings.Split(string(output), "\n")
	}()

	time.Sleep(3000 * time.Millisecond)
	args := []string{"receive", "-connect", "ssh://127.0.0.1:15432", "-key", recv_prikey, "-sender-pubkey", send_pubkey, "-overwrite", "-dir", dir}
	cmd := exec.Command("./zcretshare", args...)
	output, err := cmd.CombinedOutput()

	wg.Wait()

	actual = strings.Split(string(output), "\n")

	if err != nil {
		fmt.Printf("ACTUAL: %v\n", actual)
		fmt.Printf("EXPECTED: %v\n", expected)
		t.Fatalf("zcretshare send returned no-zero error: %v\n", err)
	}

	verify(t, actual, expected)
}

func TestSanity3(t *testing.T) {

	send_pubkey = "test/id_ecdsa_rsa_test.pub"
	recv_pubkey = "test/id_ecdsa_rsa_test.pub"

	if runtime.GOOS == "windows" {
		send_pubkey = "test\\id_ecdsa_rsa_test.pub"
		recv_pubkey = "test\\id_ecdsa_rsa_test.pub"
	}

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	fmt.Fprintln(os.Stderr, "CWD: ", exPath)

	var actual []string
	var expected []string

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		args := []string{"receive", "-listen", "127.0.0.1:15432", "-key", recv_prikey, "-sender-pubkey", send_pubkey, "-overwrite", "-dir", dir}
		cmd := exec.Command("./zcretshare", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("ACTUAL: %v\n", actual)
			fmt.Printf("EXPECTED: %v\n", expected)
			t.Fatalf("zcretshare receive returned no-zero error: %v\n", err)
		}
		actual = strings.Split(string(output), "\n")
	}()

	time.Sleep(3000 * time.Millisecond)
	args := []string{"send", "-connect", "ssh://127.0.0.1:15432", "-key", send_prikey, "-receiver-pubkey", recv_pubkey, "-in-file", infilePath + infile}
	cmd := exec.Command("./zcretshare", args...)
	output, err := cmd.CombinedOutput()

	wg.Wait()

	expected = strings.Split(string(output), "\n")

	if err != nil {
		fmt.Printf("ACTUAL: %v\n", actual)
		fmt.Printf("EXPECTED: %v\n", expected)
		t.Fatalf("zcretshare send returned no-zero error: %v\n", err)
	}

	verify(t, actual, expected)
}

func verify(t *testing.T, actual, expected []string) {

	//fmt.Printf("%v\n", actual)
	//fmt.Printf("%v\n", expected)

	var m, n string
	m = contains(actual, "Content fingerprint: SHA256:")
	n = contains(expected, "Content fingerprint: SHA256:")

	if len(m) == 0 {
		fmt.Printf("ACTUAL: %v\n", actual)
		fmt.Printf("EXPECTED: %v\n", expected)
		t.Fatalf("zcretshare receiver: Not received secret content sender\n")
	}

	if len(n) == 0 {
		fmt.Printf("ACTUAL: %v\n", actual)
		fmt.Printf("EXPECTED: %v\n", expected)
		t.Fatalf("zcretshare sender: Not received secret content (empty?) from user\n")
	}

	if m != n {
		fmt.Printf("ACTUAL: %v\n", actual)
		fmt.Printf("EXPECTED: %v\n", expected)
		t.Fatalf("zcretshare: Content fingerprint mismatch sender fp (expected): %s\t receiver fp (actual): %s\n", n, m)
	}

	cfc := false
	var clientFP string
	for _, a := range actual {
		if strings.HasPrefix(a, "Matched peer key fingerprint:") {
			cfc = true
		}

		if (cfc) && strings.HasPrefix(a, "  SHA256:") {
			clientFP = a
			break
		}
	}

	if len(clientFP) == 0 {
		t.Fatalf("zcretshare receiver: No sender fingerprint found\n")
	}

	m = contains(actual, clientFP)
	if len(m) == 0 {
		t.Fatalf("zcretshare receiver: Not matching fingerprint found, unathorized connect attempt (should have failed before we reach here)\n")
	}

	a, err := ioutil.ReadFile(dir + infile)
	if err != nil {
		t.Fatalf("zcretshare: read '%s' file failed", dir+infile)
	}

	e, err := ioutil.ReadFile(infilePath + infile)
	if err != nil {
		t.Fatalf("zcretshare: read '%s' file failed", infilePath+infile)
	}

	if !bytes.Equal(a, e) {
		fmt.Printf("ACTUAL - %s: %v\n", dir+infile, a)
		fmt.Printf("EXPECTED - %s: %v\n", infilePath+infile, e)
		t.Fatalf("zcretshare: secret file compare failed")
	}

	fi, err := os.Stat(dir + infile)
	if err != nil {
		t.Fatalf("zcretshare: output file stat failed on %s", dir+infile)
	}

	if runtime.GOOS != "windows" {
		fperm := fmt.Sprintf("%v", fi.Mode())
		if fperm != "-rw-------" {
			t.Fatalf("zcretshare: potentially insecure output file permissions: %v file:%s\n", fperm, dir+infile)
		}
	}
	_ = os.Remove(dir + infile)
}
