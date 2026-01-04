package main

import (
	"crypto/tls"
	"fmt"
	"go_ssl_checker/models"
	"log"
	"net/smtp"
	"time"
)

func main() {
	// Konfiguracija
	emailConfig := models.EmailConfig{
		SMTPServer:  "budo350.adriahost.com",
		SMTPPort:    "465",
		SenderEmail: "notifications@primea.rs",
		SenderPass:  "RxDgE5A6dBx4Q3cQZa6w",
		Recipient:   "stefan@primea.health",
	}

	certConfig := models.CertConfig{
		Domain:   "app.primea.rs",
		DaysWarn: 10,
	}

	// Ispis na konzolu da je program pokrenut
	log.Printf("SSL checker pokrenut u %s", time.Now().Format(time.RFC1123))

	// Provera sertifikata
	checkSSLCertificate(certConfig, emailConfig)
}

// checkSSLCertificate proverava validnost sertifikata preko HTTPS
func checkSSLCertificate(certConfig models.CertConfig, emailConfig models.EmailConfig) {
	// Povezivanje na server da preuzmemo sertifikat
	conn, err := tls.Dial("tcp", certConfig.Domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		errorMsg := fmt.Sprintf("Greška pri povezivanju na %s: %v", certConfig.Domain, err)
		log.Println(errorMsg)
		sendEmail(emailConfig, certConfig.Domain, -1, certConfig.DaysWarn, errorMsg)
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

// sendEmail šalje email obaveštenje koristeći SMTPS (SSL na portu 465)
func sendEmail(config models.EmailConfig, domain string, daysLeft int, daysWarn int, body string) error {
	subject := "Izveštaj: SSL sertifikat za " + domain
	if daysLeft <= daysWarn && daysLeft > -1 {
		subject = "UPOZORENJE: SSL sertifikat za " + domain + " ističe uskoro!"
	}
	message := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", config.Recipient, subject, body)

	// Uspostavljanje TLS konekcije za SMTPS (port 465)
	tlsConfig := &tls.Config{
		ServerName: config.SMTPServer,
	}
	conn, err := tls.Dial("tcp", config.SMTPServer+":"+config.SMTPPort, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Kreiranje SMTP klijenta
	client, err := smtp.NewClient(conn, config.SMTPServer)
	if err != nil {
		return err
	}
	defer client.Close()

	// Autentifikacija
	auth := smtp.PlainAuth("", config.SenderEmail, config.SenderPass, config.SMTPServer)
	if err = client.Auth(auth); err != nil {
		return err
	}

	// Slanje emaila
	if err = client.Mail(config.SenderEmail); err != nil {
		return err
	}
	if err = client.Rcpt(config.Recipient); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	client.Quit()
	return nil
}
