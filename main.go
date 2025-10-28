package main

import (
	"crypto/tls"
	"fmt"
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
	Domain   string
	DaysWarn int
}

func main() {
	// Konfiguracija
	emailConfig := EmailConfig{
		SMTPServer:  "mail.primea.rs",
		SMTPPort:    "465",
		SenderEmail: "notifications@primea.rs",
		SenderPass:  "RxDgE5A6dBx4Q3cQZa6w",
		Recipient:   "techsupport@primea.health",
	}

	certConfig := CertConfig{
		Domain:   "app.primea.rs",
		DaysWarn: 10,
	}

	// Ispis na konzolu da je program pokrenut
	log.Printf("SSL checker pokrenut u %s", time.Now().Format(time.RFC1123))

	// Provera sertifikata
	checkSSLCertificate(certConfig, emailConfig)
}

// checkSSLCertificate proverava validnost sertifikata preko HTTPS
func checkSSLCertificate(certConfig CertConfig, emailConfig EmailConfig) {
	// Povezivanje na server da preuzmemo sertifikat
	conn, err := tls.Dial("tcp", certConfig.Domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		errorMsg := fmt.Sprintf("Greška pri povezivanju na %s: %v", certConfig.Domain, err)
		log.Println(errorMsg)
		sendEmail(emailConfig, certConfig.Domain, -1, certConfig.DaysWarn, errorMsg) // Prosleđujemo DaysWarn, ali nije korišćen za greške
		return
	}
	defer conn.Close()

	// Uzimanje sertifikata
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		errorMsg := "Nema dostupnih sertifikata"
		log.Println(errorMsg)
		sendEmail(emailConfig, certConfig.Domain, -1, certConfig.DaysWarn, errorMsg)
		return
	}

	// Provera datuma isteka prvog sertifikata
	cert := certs[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	// Ispis rezultata na konzolu
	log.Printf("Sertifikat za %s: Ističe za %d dana (NotAfter: %s)", certConfig.Domain, daysLeft, cert.NotAfter.Format(time.RFC1123))
	if daysLeft <= certConfig.DaysWarn {
		log.Printf("UPOZORENJE: Sertifikat ističe uskoro (manje od %d dana)!", certConfig.DaysWarn)
	} else {
		log.Println("Sertifikat je validan.")
	}

	// Slanje emaila uvek
	body := fmt.Sprintf("Sertifikat za domen %s:\n- Preostalo dana: %d\n- Datum isteka: %s\n", certConfig.Domain, daysLeft, cert.NotAfter.Format(time.RFC1123))
	if daysLeft <= certConfig.DaysWarn {
		body += fmt.Sprintf("\nUPOZORENJE: Sertifikat ističe uskoro (manje od %d dana)!", certConfig.DaysWarn)
	} else {
		body += "\nSertifikat je validan."
	}
	err = sendEmail(emailConfig, certConfig.Domain, daysLeft, certConfig.DaysWarn, body)
	if err != nil {
		log.Printf("Greška pri slanju emaila: %v", err)
	} else {
		log.Println("Email uspešno poslat.")
	}
}

// sendEmail šalje email obaveštenje
func sendEmail(config EmailConfig, domain string, daysLeft int, daysWarn int, body string) error {
	subject := "Izveštaj: SSL sertifikat za " + domain
	if daysLeft <= daysWarn && daysLeft > -1 {
		subject = "UPOZORENJE: SSL sertifikat za " + domain + " ističe uskoro!"
	}
	message := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", config.Recipient, subject, body)

	auth := smtp.PlainAuth("", config.SenderEmail, config.SenderPass, config.SMTPServer)
	addr := config.SMTPServer + ":" + config.SMTPPort

	err := smtp.SendMail(addr, auth, config.SenderEmail, []string{config.Recipient}, []byte(message))
	return err
}
