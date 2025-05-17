import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg["Subject"] = "Teste SMTP"
msg["From"] = "teste@local"
msg["To"] = "destinatario@exemplo.com"
msg.set_content("Este é um e-mail de teste enviado sem criptografia.")

with smtplib.SMTP("localhost", 25) as server:
    server.send_message(msg)
