package models

// EmailConfig sadrži podatke za slanje emaila
type EmailConfig struct {
	SMTPServer  string
	SMTPPort    string
	SenderEmail string
	SenderPass  string // UNESITE STVARNU LOZINKU OVDE !!!
	Recipient   string
}

// CertConfig sadrži podatke o sertifikatu
type CertConfig struct {
	Domain   string
	DaysWarn int
}
