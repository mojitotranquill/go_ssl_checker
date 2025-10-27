package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/smtp"
	"time"
)

// EmailConfig sadrži podatke za slanje emaila
type EmailConfig struct {
	SMTPServer  string
	SMTPPort    string
	SenderEmail string
	SenderPass  string
	Recipient   string
}

// CertConfig sadrži podatke o sertifikatu
type CertConfig struct {
	CertPath string
	DaysWarn int
}

func main() {
	// Konfiguracija
	emailConfig := EmailConfig{
		SMTPServer:  "smtp.gmail.com",
		SMTPPort:    "587",
		SenderEmail: "your-email@gmail.com",
		SenderPass:  "your-app-password", // Koristite App Password za Gmail
		Recipient:   "recipient@example.com",
	}

	certConfig := CertConfig{
		CertPath: "/etc/letsencrypt/live/yourdomain.com/fullchain.pem",
		DaysWarn: 10,
	}

	// Provera sertifikata
	checkSSLCertificate(certConfig, emailConfig)
}

// checkSSLCertificate proverava validnost sertifikata i šalje email ako je blizu isteka
func checkSSLCertificate(certConfig CertConfig, emailConfig EmailConfig) {
	// Čitanje sertifikata
	certData, err := ioutil.ReadFile(certConfig.CertPath)
	if err != nil {
		log.Printf("Greška pri čitanju sertifikata: %v", err)
		return
	}

	// Dekodiranje PEM formata
	block, _ := pem.Decode(certData)
	if block == nil {
		log.Println("Greška: Nevalidan PEM format sertifikata")
		return
	}

	// Parsiranje sertifikata
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Greška pri parsiranju sertifikata: %v", err)
		return
	}

	// Provera datuma isteka
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysLeft <= certConfig.DaysWarn {
		err = sendEmail(emailConfig, certConfig.CertPath, daysLeft)
		if err != nil {
			log.Printf("Greška pri slanju emaila: %v", err)
		} else {
			log.Printf("Poslat email: Sertifikat ističe za %d dana", daysLeft)
		}
	} else {
		log.Printf("Sertifikat je validan još %d dana", daysLeft)
	}
}

// sendEmail šalje email obaveštenje
func sendEmail(config EmailConfig, certPath string, daysLeft int) error {
	subject := "Upozorenje: SSL sertifikat ističe"
	body := fmt.Sprintf("Sertifikat na putanji %s ističe za %d dana!", certPath, daysLeft)
	message := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", config.Recipient, subject, body)

	auth := smtp.PlainAuth("", config.SenderEmail, config.SenderPass, config.SMTPServer)
	addr := config.SMTPServer + ":" + config.SMTPPort

	err := smtp.SendMail(addr, auth, config.SenderEmail, []string{config.Recipient}, []byte(message))
	return err
}
