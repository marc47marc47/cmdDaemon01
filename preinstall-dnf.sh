sudo dnf install -y gcc openssl-devel make
sudo dnf install -y git
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y openssl-devel
sudo firewall-cmd --add-port=4433/tcp --permanent

