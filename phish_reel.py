import smtplib
import traceback
from socket import gaierror
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import os
import configparser

os.chdir(os.path.dirname(__file__))

FORMAT = "%(asctime)s: %(levelname)s: %(message)s (File %(filename)s: Function %(funcName)s: Line %(lineno)d)"
logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt='%H:%M:%S')

class SMTPConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket  = host + ':' + port
        self.server  = None
        self.sender = None
        self.recipients = None

        self.__connect()
        self.__start_tls()
        self.__eval_server_features()

    def __ehlo(self):
        try:
            self.server.ehlo()
            if not self.server.does_esmtp:
                logging.critical('The server does not support ESMTP')
                exit(1)
        except smtplib.SMTPHeloError:
            logging.critical('The server did not reply properly to the EHLO/HELO greeting.')
            exit(1)

    def __connect(self):
        try:
            logging.info('Connecting to SMTP socket (' + self.socket + ')...')
            self.server = smtplib.SMTP(self.host, self.port)
        except (gaierror, OSError):
            logging.critical('Unable to establish connection to SMTP socket.')
            exit(1)

    def __start_tls(self):
        self.__ehlo()
        if not self.server.has_extn('starttls'):
            logging.critical('SMTP server does not support TLS.')
            exit(1)
        else:
            try:
                logging.info('Starting TLS session...')
                self.server.starttls()
            except RuntimeError:
                logging.critical('SSL/TLS support is not available to your Python interpreter.')
                exit(1)

    def __eval_server_features(self):
        self.__ehlo()

        if not self.server.has_extn('auth'):
            logging.critical('No AUTH types detected.')
            exit(1)

        server_auth_features = self.server.esmtp_features.get('auth').strip().split()
        supported_auth_features = { auth_type for auth_type in {'PLAIN', 'LOGIN'} if auth_type in server_auth_features }

        if not supported_auth_features:
            logging.critical('SMTP server does not support AUTH PLAIN or AUTH LOGIN.')
            exit(1)

    def login(self, username, password):
        try:
            return self.server.login(username, password)
        except smtplib.SMTPAuthenticationError:
            logging.critical('The server did not accept the username/password combination.')
            return False
        except smtplib.SMTPNotSupportedError:
            logging.critical('The AUTH command is not supported by the server.')
            exit(1)
        except smtplib.SMTPException:
            logging.critical('Encountered an error during authentication.')
            exit(1)

    def compose_message(self, sender, name, recipients, subject, html):
        self.sender = sender
        self.recipients = recipients

        message = MIMEMultipart('alternative')
        message.set_charset("utf-8")

        message["From"] = name + "<" +  self.sender + ">"
        message['Subject'] = subject
        message["To"] = ', '.join(self.recipients)

        body = MIMEText(html, 'html')
        message.attach(body)
        return message

    def send_mail(self, message):
        output = ""
        try:
            logging.info('Sending spoofed message...')
            self.server.sendmail(self.sender, self.recipients, message.as_string())
            logging.info('Message sent!')
            output = "Message sent!"
        except smtplib.SMTPException as e:
            logging.critical('Unable to send message. Check sender, recipients and message body')
            logging.critical(traceback.format_exc())
            output = f"Unable to Send Message: {e}"
        return output


def get_creds(email_nickname):
    config = configparser.ConfigParser()
    if os.path.isfile("localonly.phish_reel.config"):
        config.read("localonly.phish_reel.config")
    else:
        config.read("phish_reel.config")
    from_name = config[email_nickname]["name"]
    from_email = config[email_nickname]["email"]
    port = config[email_nickname]["port"]
    server = config[email_nickname]["server"]
    username = config[email_nickname]["username"]
    password = config[email_nickname]["password"]
    return from_name, from_email, port, server, username, password

def send_email(to_email, subject, content, from_email_nickname, from_name=None):
    logging.info(f"Sending message to {to_email}")
    from_name_, from_email, port, server, username, password = get_creds(from_email_nickname)
    if from_name is None: from_name = from_name_
    conn = SMTPConnection(server, port) #Ports: 25, 587, 465
    conn.login(username, password)
    m = conn.compose_message(from_email, from_name, [to_email], subject, content)
    return conn.send_mail(m)

def get_email_options():
    config = configparser.ConfigParser()
    if os.path.isfile("localonly.phish_reel.config"):
        config.read("localonly.phish_reel.config")
    else:
        config.read("phish_reel.config")
    email_list = []
    for key in config.keys():
        if key != "DEFAULT":
            email_list.append([key, config[key]["name"], config[key]["email"]])
    # try: email_list.remove("DEFAULT")
    # except: pass
    return email_list

# print(get_email_options())

# Usage Example 1
# to_email = "johnnytest@test.com"
# send_email(to_email, "URGENT: Sign me", "I need you to sign this", "sb")

# Usage Example 2
# to_email = "johnnytest@test.com"
# with open("email_content.html", "r") as file:
#     send_email(to_email, "URGENT: Sign me", file.read(), "sb")
