package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

var Opts struct {
	TRC             string `short:"t" long:"trc" description:"The current TRC of the ISD" required:"true"`
	Cert            string `short:"c" long:"cert" description:"Input certificate" required:"true"`
	Key             string `short:"k" long:"key" description:"Input key" required:"true"`
	RenewBeforeDays int64  `short:"d" long:"days" description:"Renew certificate if it expires before X days" required:"true"`
	LogLevel        string `short:"l" long:"logLevel" description:"Log-level (ERROR|WARN|INFO|DEBUG|TRACE)" default:"INFO"`
}

func configureLogging() error {
	l, err := log.ParseLevel(Opts.LogLevel)
	if err != nil {
		return err
	}
	log.SetLevel(l)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	log.SetOutput(os.Stdout)
	return nil
}

func mustParseFlags() {
	p := flags.NewParser(&Opts, flags.HelpFlag)
	p.Usage = "scionlab-cert-renewer [OPTIONS]"
	p.ShortDescription = "scionlab-cert-renewer - Checks the given certificate to expire within the configured deadline, and renew via scion-pki"
	p.LongDescription = "scionlab-cert-renewer - Checks the given certificate to expire within the configured deadline, and renew via scion-pki"
	// err is containing the usage description
	_, err := p.Parse()
	if err != nil {
		fmt.Println(err) // here we don't use log because we dont want any timestamps or similar being printed
		os.Exit(1)
	}
}

// TODO: Add cronjob
func main() {
	logrus.Info("Starting scionlab-cert-renewer")
	mustParseFlags()
	configureLogging()

	logrus.Info("[Renewer] Checking cert ", Opts.Cert, " to expire within ", Opts.RenewBeforeDays, " days")
	expiresSoon, err := checkIfCertExpiresSoon(Opts.Cert)
	if err != nil {
		log.Fatal(fmt.Errorf("[Renewer] Failed to check cert %s for expiration, %s", Opts.Cert, err))
	}

	if !expiresSoon {
		logrus.Info("[Renewer] Cert is not expiring in the configured deadline, skipping the rest...")
		return
	}

	logrus.Info("[Renewer] Prepare to renew cert ", Opts.Cert, " into tmp dir")
	outCert, err := os.CreateTemp(os.TempDir(), "*.crt")
	if err != nil {
		log.Fatal(err)
	}
	outKey, err := os.CreateTemp(os.TempDir(), "*.key")
	if err != nil {
		log.Fatal(err)
	}

	logrus.Info("[Renewer] Renew to cert ", outKey.Name(), " and key ", outKey.Name())
	err = renewCert(outCert.Name(), outKey.Name())
	if err != nil {
		log.Fatal(err)
	}

	logrus.Info("[Renewer] Obtained new cert and key")
	logrus.Info("[Renewer] Validating new cert")
	err = validateCert(outCert.Name())
	if err != nil {
		log.Fatal(err)
	}
	logrus.Info("[Renewer] Validating done")

	logrus.Info("[Renewer] Verifying new cert")
	err = validateCert(outCert.Name())
	if err != nil {
		log.Fatal(err)
	}
	logrus.Info("[Renewer] Verifying done")
	logrus.Info("[Renewer] Copy tmp files back to original certs")

	err = os.Rename(outCert.Name(), Opts.Cert)
	if err != nil {
		log.Fatal(err)
	}

	err = os.Rename(outKey.Name(), Opts.Key)
	if err != nil {
		log.Fatal(err)
	}
	logrus.Info("[Renewer] Done")
}

func checkIfCertExpiresSoon(file string) (bool, error) {
	r, _ := ioutil.ReadFile(file)
	block, _ := pem.Decode(r)

	expires := time.Duration(time.Duration(Opts.RenewBeforeDays) * time.Hour)
	deadline := time.Now().Add(expires)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	return deadline.After(cert.NotAfter), nil
}

func executeCmd(command string, args ...string) (error, string, string) {
	cmd := exec.Command(command, args...)
	var out bytes.Buffer
	var stdErr bytes.Buffer
	cmd.Stderr = &stdErr
	cmd.Stdout = &out
	log.Debugf("[Renewer] Executing: %s\n", cmd.String())
	err := cmd.Run()
	if err == nil {
		log.Debugf("[Renewer] Execute successful")
	} else {
		log.Debugf("[Renewer] Execute failed %s", err.Error())
	}
	return err, out.String(), stdErr.String()
}

// XXX We might want to include the respective code from scion-pki here later, but for now it's just blocking...
func validateCert(file string) error {

	err, strOut, strErr := executeCmd("scion-pki", "certificate", "validate", "--type", "chain", file)
	if err != nil {
		return fmt.Errorf("[Renewer] Failed to validate via scion-pki %s, err: %s", err, strErr)
	}
	logrus.Debug("[Renewer] ", strOut)
	return nil
}

func verifyCert(file string) error {
	err, strOut, strErr := executeCmd("scion-pki", "certificate", "verify", "--trc", Opts.TRC, file)
	if err != nil {
		return fmt.Errorf("[Renewer]: Failed to verify via scion-pki %s, err: %s", err, strErr)
	}
	logrus.Debug("[Renewer] ", strOut)
	return nil
}

func renewCert(outCert string, outKey string) error {
	err, strOut, strErr := executeCmd("scion-pki", "certificate", "renew", Opts.Cert, Opts.Key, "--out", outCert, "--out-key", outKey, "--trc", Opts.TRC)
	if err != nil {
		return fmt.Errorf("[Renewer]: Failed to renew via scion-pki %s, err: %s", err, strErr)
	}
	logrus.Debug("[Renewer] ", strOut)
	return nil
}
