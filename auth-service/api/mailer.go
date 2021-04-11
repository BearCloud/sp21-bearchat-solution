package api

import (
	"bytes"
	"html/template"
	"os"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// A Mailer is something that allows us to send emails that use an HTML template using the files in `/templates`.
// Note our project is configured to only have a single Mailer which is from SendGrid, so why is
// it that we made our code work with this interface instead of just using SendGrid directly?
//
// The answer is that it makes our code easier to extend in the future. If you wanted to add more
// Mailers, then you only need to make some struct with a SendEmail method and your code will
// handle it automatically. Additionally, this allows us to *mock* the Mailer in our tests
// so we don't send actual emails out to people while testing (sometimes an API can charge or
// ban you if you make too many requests). This is part of a software engineering principle
// called Dependency Injection.
type Mailer interface {
	// SendEmail sends an email to the recipient with the specified subject
	SendEmail(recipient string, subject string, templatePath string, data map[string]interface{}) error
}

// A Struct that contains all the information needed to send an email using SendGrid.
type SendGridMailer struct {
	client *sendgrid.Client
	sender *mail.Email
	scheme string
}

// InitMailer initalizes the SendGrid client with default settings. Make sure to actually place a SENDGRID_KEY
// into an .env file next to main.go so the code can log you in! Also add in a SENDER_EMAIL!
func NewSendGridMailer() SendGridMailer {
	return SendGridMailer{sendgrid.NewSendClient(os.Getenv("SENDGRID_KEY")),
		mail.NewEmail("DevOps At Berkeley", os.Getenv("SENDER_EMAIL")),
		"http",
	}
}

// This SendEmail function uses SendGrid to send an email.
func (m SendGridMailer) SendEmail(recipient string, subject string, templatePath string, data map[string]interface{}) error {
	// Parse template file and execute with data.
	var html bytes.Buffer
	tmpl, err := template.ParseFiles("./api/templates/" + templatePath)
	if err != nil {
		return err
	}
	err = tmpl.Execute(&html, data)
	if err != nil {
		return err
	}

	//turn our html page buffer into a string
	plainTextContent := html.String()
	recipientEmail := mail.NewEmail("recipient", recipient)

	// Construct and send email via Sendgrid.
	message := mail.NewSingleEmail(m.sender, subject, recipientEmail, plainTextContent, html.String())

	_, err = m.client.Send(message)
	return err
}
