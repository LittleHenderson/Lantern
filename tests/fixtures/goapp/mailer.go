package main

type SMTPMailer struct{}

func (m *SMTPMailer) Send(to, body string) error {
	return nil
}
