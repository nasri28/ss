#!/usr/bin/env bash
# Detection area
# ------------------------------------------------- ------------
# Check the system
export LANG = en_US.UTF-8

echoContent() {
	case $1 in
	# Red
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# sky blue
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# green
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		# White
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# Yellow
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
checkSystem() {
	if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
		mkdir -p /etc/yum.repos.d

		if [[ -f "/etc/centos-release" ]]; then
			centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

			if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
				centosVersion=8
			be
		be

		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"

	elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
		release="debian"
		installType='apt -y install'
		upgrade="apt update"
		removeType = 'apt -y autoremove'

	elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
		release="ubuntu"
		installType='apt -y install'
		upgrade="apt update"
		removeType = 'apt -y autoremove'
		if grep </etc/issue -q -i "16."; then
			release=
		be
	be

	if [[ -z ${release} ]]; then
		echoContent red "\nThis script does not support this system, please report the following log to the developer\n"
		echoContent yellow "$(cat /etc/issue)"
		echoContent yellow "$(cat /proc/version)"
		exit 0
	be
}

# Check the CPU provider
checkCPUVendor() {
	if [[ -n $(which uname) ]]; then
		if [[ "$(uname)" == "Linux" ]]; then
			case "$(uname -m)" in
			'amd64' | 'x86_64')
				xrayCoreCPUVendor="Xray-linux-64"
				v2rayCoreCPUVendor="v2ray-linux-64"
				trojanGoCPUVendor="trojan-go-linux-amd64"
				;;
			'armv8' | 'aarch64')
				xrayCoreCPUVendor="Xray-linux-arm64-v8a"
				v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
				trojanGoCPUVendor="trojan-go-linux-armv8"
				;;
			*)
				echo "This CPU architecture is not supported--->"
				exit 1
				;;
			esac
		be
	else
		echoContent red "Unable to recognize this CPU architecture, default amd64, x86_64--->"
		xrayCoreCPUVendor="Xray-linux-64"
		v2rayCoreCPUVendor="v2ray-linux-64"
		trojanGoCPUVendor="trojan-go-linux-amd64"
	be
}

# Initialize global variables
initVar () {
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	# Core supported cpu version
	xrayCoreCPUVendor=""
	v2rayCoreCPUVendor=""
	trojanGoCPUVendor=""
	# Domain name
	domain=

	# CDN node address
	add=

	# Total installation progress
	totalProgress = 1

	# 1.xray-core installation
	# 2.v2ray-core installation
	# 3.v2ray-core[xtls] Installation
	coreInstallType=

	# Core installation path
	# coreInstallPath=

	# v2ctl Path
	ctlPath=
	# 1. Install all
	# 2. Personalized installation
	# v2rayAgentInstallType =

	# Current personalized installation method 01234
	currentInstallProtocolType=

	# Pre-type
	frontingType=

	# Choose a personalized installation method
	selectCustomInstallType=

	# v2ray-core, xray-core configuration file path
	configPath=

	# Configuration file path
	currentPath=

	# Configuration file host
	currentHost=

	# Core type selected during installation
	selectCoreType=

	# Default core version
	v2rayCoreVersion=

	# Random path
	customPath=

	# centos version
	centosVersion=

	# UUID
	currentUUID=

	localIP =

	# Integrated renewal certificate logic no longer uses a separate script--RenewTLS
	renewTLS=$1

	# tls Number of attempts after failed installation
	installTLSCount=
}

# Detect installation method
readInstallType() {
	coreInstallType=
	configPath=

	# 1. Detect the installation directory
	if [[ -d "/etc/v2ray-agent" ]]; then
		# Detect installation method v2ray-core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then
				configPath=/etc/v2ray-agent/v2ray/conf/

				if ! grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# V2ray-core without XTLS
					coreInstallType=2
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				elif grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# V2ray-core with XTLS
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
					coreInstallType=3
				be
			be
		be

		if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
			# Check xray-core here
			if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
				# xray-core
				configPath=/etc/v2ray-agent/xray/conf/
				ctlPath=/etc/v2ray-agent/xray/xray
				coreInstallType=1
			be
		be
	be
}

# Read protocol type
readInstallProtocolType() {
	currentInstallProtocolType=

	while read -r row; do
		if echo "${row}" | grep -q 02_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'trojan'
			frontingType=02_trojan_TCP_inbounds
		be
		if echo "${row}" | grep -q VLESS_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'0'
			frontingType=02_VLESS_TCP_inbounds
		be
		if echo "${row}" | grep -q VLESS_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'1'
		be
		if echo "${row}" | grep -q trojan_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'2'
		be
		if echo "${row}" | grep -q VMess_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'3'
		be
		if echo "${row}" | grep -q 04_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'4'
		be
		if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'5'
		be
	done < <(find ${configPath} -name "*inbounds.json" | awk -F "[.]" '{print $1}')
}

# Check the file directory and path path
readConfigHostPathUUID () {
	currentPath=
	currentUUID=
	currentHost=
	currentPort=
	currentAdd=
	# Read path
	if [[ -n "${configPath}" ]]; then
		local fallback
		fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

		local path
		path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

		if [[ $(echo "${fallback}" | jq -r .dest) == 31297 ]]; then
			currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31298 ]]; then
			currentPath=$(echo "${path}" | awk -F "[t][c][p]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31299 ]]; then
			currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
		be
	be

	if [[ "${coreInstallType}" == "1" ]]; then
		currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		be
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		if [[ "${coreInstallType}" == "3" ]]; then
			currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		else
			currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		be
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)

		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		be
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
	be
}

# Status display
showInstallStatus() {
	if [[ -n "${coreInstallType}" ]]; then
		if [[ "${coreInstallType}" == 1 ]]; then
			if [[ -n $(pgrep -f xray/xray) ]]; then
				echoContent yellow "\nCore: Xray-core[running]"
			else
				echoContent yellow "\nCore: Xray-core[not running]"
			be

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == 3 ]]; then
			if [[ -n $(pgrep -f v2ray/v2ray) ]]; then
				echoContent yellow "\nCore: v2ray-core[running]"
			else
				echoContent yellow "\nCore: v2ray-core[not running]"
			be
		be
		# Read protocol type
		readInstallProtocolType

		if [[ -n ${currentInstallProtocolType} ]]; then
			echoContent yellow "Protocol installed: \c"
		be
		if echo ${currentInstallProtocolType} | grep -q 0; then
			if [[ "${coreInstallType}" == 2 ]]; then
				echoContent yellow "VLESS+TCP[TLS] \c"
			else
				echoContent yellow "VLESS+TCP[TLS/XTLS] \c"
			be
		be

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			if [[ "${coreInstallType}" == 1 ]]; then
				echoContent yellow "Trojan+TCP[TLS/XTLS] \c"
			be
		be

		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent yellow "VLESS+WS[TLS] \c"
		be

		if echo ${currentInstallProtocolType} | grep -q 2; then
			echoContent yellow "Trojan+gRPC[TLS] \c"
		be

		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent yellow "VMess+WS[TLS] \c"
		be

		if echo ${currentInstallProtocolType} | grep -q 4; then
			echoContent yellow "Trojan+TCP[TLS] \c"
		be

		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent yellow "VLESS+gRPC[TLS] \c"
		be
	be
}

# Clean up old residue
cleanUp() {
	if [[ "$1" == "v2rayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/v2ray/* | grep -E '(config_full.json|conf)')"
		handleV2Ray stop >/dev/null
		rm -f /etc/systemd/system/v2ray.service
	elif [[ "$1" == "xrayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/xray/* | grep -E '(config_full.json|conf)')"
		handleXray stop >/dev/null
		rm -f /etc/systemd/system/xray.service

	elif [[ "$1" == "v2rayDel" ]]; then
		rm -rf /etc/v2ray-agent/v2ray/*

	elif [[ "$1" == "xrayDel" ]]; then
		rm -rf /etc/v2ray-agent/xray/*
	be
}

initVar "$1"
checkSystem
checkCPUVendor
readInstallType
readInstallProtocolType
readConfigHostPathUUID

# ------------------------------------------------- ------------

# Initialize the installation directory
mkdirTools() {
	mkdir -p /etc/v2ray-agent/tls
	mkdir -p /etc/v2ray-agent/subscribe
	mkdir -p /etc/v2ray-agent/subscribe_tmp
	mkdir -p /etc/v2ray-agent/v2ray/conf
	mkdir -p /etc/v2ray-agent/xray/conf
	mkdir -p /etc/v2ray-agent/trojan
	mkdir -p /etc/systemd/system/
	mkdir -p /tmp/v2ray-agent-tls/
}

# Installation kit
installTools() {
	echo'installation tool'
	echoContent skyBlue "\nProgress$1/${totalProgress}: installation tool"
	# Fix ubuntu individual system problems
	if [[ "${release}" == "ubuntu" ]]; then
		dpkg --configure -a
	be

	if [[ -n $(pgrep -f "apt") ]]; then
		pgrep -f apt | xargs kill -9
	be

	echoContent green "---> Check and install updates [The new machine will be very slow. If there is no response for a long time, please stop it manually and execute it again]"

	${upgrade} >/dev/null 2>&1
	if [[ "${release}" == "centos" ]]; then
		rm -rf /var/run/yum.pid
		${installType} epel-release >/dev/null 2>&1
	be

	#	[[ -z `find /usr/bin /usr/sbin |grep -v grep|grep -w curl` ]]

	if ! find /usr/bin /usr/sbin | grep -q -w wget; then
		echoContent green "---> install wget"
		${installType} wget >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w curl; then
		echoContent green "---> install curl"
		${installType} curl >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
		echoContent green "---> install unzip"
		${installType} unzip >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w socat; then
		echoContent green "---> install socat"
		${installType} socat >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w tar; then
		echoContent green "---> install tar"
		${installType} tar >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w cron; then
		echoContent green "---> install crontabs"
		if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
			${installType} cron >/dev/null 2>&1
		else
			${installType} crontabs >/dev/null 2>&1
		be
	be
	if ! find /usr/bin /usr/sbin | grep -q -w jq; then
		echoContent green "---> install jq"
		${installType} jq >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
		echoContent green "---> install binutils"
		${installType} binutils >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
		echoContent green "---> install ping6"
		${installType} inetutils-ping >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
		echoContent green "---> install qrencode"
		${installType} qrencode >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
		echoContent green "---> install sudo"
		${installType} sudo >/dev/null 2>&1
	be

	if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
		echoContent green " ---> 安装lsb-release"
		${installType} lsb-release >/dev/null 2>&1
	be

	# Detect the nginx version and provide the option of uninstalling

	if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
		echoContent green "---> install nginx"
		installNginxTools
	else
		nginxVersion=$(nginx -v 2>&1)
		nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
		if [[ ${nginxVersion} -lt 14 ]]; then
			read -r -p "It is read that the current Nginx version does not support gRPC, which will cause the installation to fail. Do you want to uninstall Nginx and reinstall it? [y/n]:" unInstallNginxStatus
			if [[ "${unInstallNginxStatus}" == "y" ]]; then
				${removeType} nginx >/dev/null 2>&1
				echoContent yellow "---> nginx uninstall complete"
				echoContent green "---> install nginx"
				installNginxTools >/dev/null 2>&1
			else
				exit 0
			be
		be
	be
	if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
		echoContent green "---> install semanage"
		${installType} bash-completion >/dev/null 2>&1

		if [[ "${centosVersion}" == "7" ]]; then
			policyCoreUtils="policycoreutils-python.x86_64"
		elif [[ "${centosVersion}" == "8" ]]; then
			policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
		be

		if [[ -n "${policyCoreUtils}" ]]; then
			${installType} ${policyCoreUtils} >/dev/null 2>&1
		be
		if [[ -n $(which semanage) ]]; then
			semanage port -a -t http_port_t -p tcp 31300

		be
	be

	if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
		echoContent green "---> install acme.sh"
		curl -s https://get.acme.sh | sh -s >/etc/v2ray-agent/tls/acme.log 2>&1
		if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
			echoContent red "acme installation failed --->"
			tail -n 100 /etc/v2ray-agent/tls/acme.log
			echoContent yellow "Error troubleshooting:"
			echoContent red "1. Failed to get the Github file, please wait for Gitub to recover and try again, the recovery progress can be viewed [https://www.githubstatus.com/]"
			echoContent red "2. There is a bug in the acme.sh script, please check [https://github.com/acmesh-official/acme.sh] issues"
			exit 0
		be
	be
}

# Install Nginx
installNginxTools() {

	if [[ "${release}" == "debian" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl = http: //nginx.org/packages/centos/ \ $ releasever/\ $ basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl = http: //nginx.org/packages/mainline/centos/ \ $ releasever/\ $ basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
		sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
	be
	${installType} nginx >/dev/null 2>&1
	systemctl daemon-reload
	systemctl enable nginx
}

# Install warp
installWarp() {
	${installType} gnupg2 -y >/dev/null 2>&1
	if [[ "${release}" == "debian" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		sudo rpm -ivh "http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm" >/dev/null 2>&1
	be

	echoContent green "---> Install WARP"
	${installType} cloudflare-warp >/dev/null 2>&1
	if [[ -z $(which warp-cli) ]]; then
		echoContent red "---> WARP installation failed"
		exit 0
	be
	systemctl enable warp-svc
	warp-cli --accept-tos register
	warp-cli --accept-tos set-mode proxy
	warp-cli --accept-tos set-proxy-port 31303
	warp-cli --accept-tos connect
	#	if [[]];then
	# fi
	# todo curl --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace
	# systemctl daemon-reload
	# systemctl enable cloudflare-warp
}
# Initialize Nginx application certificate configuration
initTLSNginxConfig() {
	handleNginx stop
	echoContent skyBlue "\nProgress$1/${totalProgress}: Initialize Nginx application certificate configuration"
	if [[ -n "${currentHost}" ]]; then
		echo
		read -r -p "Read the last installation record, whether to use the domain name of the last installation? [y/n]:" historyDomainStatus
		if [[ "${historyDomainStatus}" == "y" ]]; then
			domain=${currentHost}
			echoContent yellow "\n ---> Domain name: ${domain}"
		else
			echo
			echoContent yellow "Please enter the domain name to be configured. Example: www.v2ray-agent.com --->"
			read -r -p "domain name:" domain
		be
	else
		echo
		echoContent yellow "Please enter the domain name to be configured. Example: www.v2ray-agent.com --->"
		read -r -p "domain name:" domain
	be

	if [[ -z ${domain} ]]; then
		echoContent red "Domain name cannot be empty--->"
		initTLSNginxConfig
	else
		# Change setting
		touch /etc/nginx/conf.d/alone.conf
		cat <<EOF >/etc/nginx/conf.d/alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {
    	allow all;
    }
    location /test {
    	return 200 'fjkvymb6len';
    }
	location /ip {
		proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header REMOTE-HOST \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		default_type text/plain;
		return 200 \$proxy_add_x_forwarded_for;
	}
}
EOF
		# Start nginx
		handleNginx start
		checkIP
	be
}

# Modify nginx redirect configuration
updateRedirectNginxConf() {

	cat <<EOF >/etc/nginx/conf.d/alone.conf
server {
	listen 80;
	listen [::]:80;
	server_name ${domain};
	# shellcheck disable=SC2154
	return 301 https://${domain}\${request_uri};
}
server {
		listen 127.0.0.1:31300;
		server_name _;
		return 403;
}
EOF

	if echo "${selectCustomInstallType}" | grep -q 2 && echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }

    location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
}
EOF
	elif echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then
		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF

	elif echo "${selectCustomInstallType}" | grep -q 2 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF
	else

		cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location / {
	}
}
EOF
	be

	cat <<EOF >>/etc/nginx/conf.d/alone.conf
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
		add_header Content-Type text/plain;
		alias /etc/v2ray-agent/subscribe/;
	}
	location / {
		add_header Strict-Transport-Security "max-age=15552000; preload" always;
	}
}
EOF

}

# Check ip
checkIP() {
	echoContent skyBlue "\n ---> Check the domain name ip"
	localIP=$(curl -s -m 2 "${domain}/ip")
	handleNginx stop
	if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
		echoContent red "\n ---> The ip of the current domain name is not detected"
		echoContent yellow "---> Please check if the domain name is written correctly"
		echoContent yellow "---> Please check the domain name dns resolution is correct"
		echoContent yellow "---> If the resolution is correct, please wait for the dns to take effect, it is expected to take effect within three minutes"
		echoContent yellow "---> If the above settings are correct, please reinstall the pure system and try again"
		if [[ -n ${localIP} ]]; then
			echoContent yellow "---> abnormal return value detected"
		be
		echoContent red "---> Please check if the firewall is turned off\n"
		read -r -p "Do you want to turn off the firewall through a script? [y/n]:" disableFirewallStatus
		if [[ ${disableFirewallStatus} == "y" ]]; then
			handleFirewall stop
		be

		exit 0
	be

	if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q ":"; then
		echoContent red "\n ---> Multiple ips detected, please confirm whether to close cloudflare's cloud"
		echoContent yellow "---> wait three minutes after closing the cloud and try again"
		echoContent yellow "---> The detected ip is as follows: [${localIP}]"
		exit 0
	be

	echoContent green "---> The current domain name ip is: [${localIP}]"
}
# Install TLS
installTLS() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Apply for TLS certificate\n"
	local tlsDomain=${domain}
	# Install tls
	if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
		# Existing certificate
		echoContent green "---> certificate detected"
		checkTLStatus "$ {tlsDomain}"
		if [[ "${tlsStatus}" == "Expired" ]]; then
			rm -rf "$HOME/.acme.sh/${tlsDomain}_ecc/*"
			rm -rf "/etc/v2ray-agent/tls/${tlsDomain}*"
			installTLS "$1"
		else
			echoContent green "---> The certificate is valid"
			#
			if [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
				sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
			else
				echoContent yellow "---> If it has not expired, please select [n]\n"
				read -r -p "Do you want to reinstall? [y/n]:" reInstallStatus
				if [[ "${reInstallStatus}" == "y" ]]; then
					rm -rf /etc/v2ray-agent/tls/*
					installTLS "$1"
				be
			be
		be
	elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
		echoContent green "---> Install TLS certificate"
		if echo "${localIP}" | grep -q ":"; then
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt --listen-v6 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
		else
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
		be

		if [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		be
		if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			tail -n 10 /etc/v2ray-agent/tls/acme.log
			if [[ ${installTLSCount} == "1" ]]; then
				echoContent red "---> TLS installation failed, please check acme log"
				exit 0
			be
			echoContent red "---> TLS installation failed, check the firewall"
			handleFirewall stop
			echoContent yellow "---> try to install the TLS certificate again"
			installTLSCount=1
			installTLS "$1"
		be
		echoContent green "---> TLS generated successfully"
	else
		echoContent yellow "---> acme.sh is not installed"
		exit 0
	be
}
# Configure disguise blog
initNginxConfig() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Configure Nginx"

	cat <<EOF >/etc/nginx/conf.d/alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {allow all;}
    location /test {return 200 'fjkvymb6len';}
}
EOF
}

# Custom/random path
randomPathFunction() {
	echoContent skyBlue "\nProgress $1/${totalProgress}: Generate random path"

	if [[ -n "${currentPath}" ]]; then
		echo
		read -r -p "Read the last installation record, whether to use the path path of the last installation? [y/n]:" historyPathStatus
		echo
	be

	if [[ "${historyPathStatus}" == "y" ]]; then
		customPath=${currentPath}
		echoContent green "---> Successfully used\n"
	else
		echoContent yellow "Please enter a custom path [example: alone], no slash is needed, [Enter] random path"
		read -r -p'Path:' customPath

		if [[ -z "${customPath}" ]]; then
			customPath=$(head -n 50 /dev/urandom | sed 's/[^a-z]//g' | strings -n 4 | tr '[:upper:]' '[:lower:]' | head -1)
			currentPath=${customPath:0:4}
			customPath=${currentPath}
		else
			currentPath=${customPath}
		be

	be
	echoContent yellow "\n path：${currentPath}"
	echoContent skyBlue "\n----------------------------"
}
# Nginx disguise blog
nginxBlog () {
	echoContent skyBlue "\nProgress $1/${totalProgress}: Add a fake site"
	if [[ -d "/usr/share/nginx/html" && -f "/usr/share/nginx/html/check" ]]; then
		echo
		read -r -p "Detected the installation of a fake site, do you need to reinstall [y/n]:" nginxBlogInstallStatus
		if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
			rm -rf /usr/share/nginx/html
			randomNum=$((RANDOM % 6 + 1))
			wget -q -P /usr/share/nginx https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
			unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
			rm -f /usr/share/nginx/html${randomNum}.zip*
			echoContent green "---> Successfully added camouflage site"
		be
	else
		randomNum=$((RANDOM % 6 + 1))
		rm -rf /usr/share/nginx/html
		wget -q -P /usr/share/nginx https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
		unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
		rm -f /usr/share/nginx/html${randomNum}.zip*
		echoContent green "---> Successfully added camouflage site"
	be

}
# Operate Nginx
handleNginx() {

	if [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
		nginx
		sleep 0.5

		if [[ -z $(pgrep -f nginx) ]]; then
			echoContent red "---> Nginx failed to start"
			echoContent red "---> Please try to install nginx manually and execute the script again"
			exit 0
		be
	elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then
		nginx -s stop >/dev/null 2>&1
		sleep 0.5
		if [[ -n $(pgrep -f "nginx") ]]; then
			pgrep -f "nginx" | xargs kill -9
		be
	be
}

# Timing task to update tls certificate
installCronTLS() {
	echoContent skyBlue "\nProgress $1/${totalProgress}: add regular maintenance certificate"
	crontab -l >/etc/v2ray-agent/backup_crontab.cron
	local historyCrontab
	historyCrontab=$(but not '/v2ray-agent/d;/acme.sh/d', /etc/v2ray-agent/backup_crontab.cron)
	echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
	echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
	crontab /etc/v2ray-agent/backup_crontab.cron
	echoContent green "\n ---> Succeeded in adding scheduled maintenance certificate"
}

# Update certificate
renewalTLS() {
	echoContent skyBlue "\nProgress 1/1: Update certificate"

	if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
		modifyTime=$(stat "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff = currentTime - modifyTime))
		((days = stampDiff / 86400))
		((remainingDays = 90 - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			tlsStatus="Expired"
		be

		echoContent skyBlue "---> certificate check date: $(date "+%F %H:%M:%S")"
		echoContent skyBlue "---> certificate generation date: $(date -d @"${modifyTime}" +"%F %H:%M:%S")"
		echoContent skyBlue "---> days for certificate generation: ${days}"
		echoContent skyBlue "---> The remaining days of the certificate: "${tlsStatus}
		echoContent skyBlue "---> Automatic update on the last day before the certificate expires, if the update fails, please update manually"

		if [[ ${remainingDays} -le 1 ]]; then
			echoContent yellow "---> Regenerate the certificate"
			handleNginx stop
			sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${currentHost}" --fullchainpath /etc/v2ray-agent/tls/"${currentHost}.crt" --keypath /etc/v2ray-agent/tls/"${currentHost}.key" --ecc
			reloadCore
		else
			echoContent green "---> The certificate is valid"
		be
	else
		echoContent red "---> not installed"
	be
}
# View the status of the TLS certificate
checkTLStatus() {

	if [[ -n "$1" ]]; then
		if [[ -d "$HOME/.acme.sh/$1_ecc" ]] && [[ -f "$HOME/.acme.sh/$1_ecc/$1.key" ]] && [[ -f "$HOME/.acme.sh/$1_ecc/$1.cer" ]]; then
			modifyTime=$(stat "$HOME/.acme.sh/$1_ecc/$1.key" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

			modifyTime=$(date +%s -d "${modifyTime}")
			currentTime=$(date +%s)
			((stampDiff = currentTime - modifyTime))
			((days = stampDiff / 86400))
			((remainingDays = 90 - days))

			tlsStatus=${remainingDays}
			if [[ ${remainingDays} -le 0 ]]; then
				tlsStatus="Expired"
			be
			echoContent skyBlue "---> certificate generation date: $(date -d "@${modifyTime}" +"%F %H:%M:%S")"
			echoContent skyBlue "---> days for certificate generation: ${days}"
			echoContent skyBlue "---> The remaining days of the certificate: ${tlsStatus}"
		be
	be
}

# Install V2Ray, specified version
installV2Ray() {
	readInstallType
	echoContent skyBlue "\nProgress$1/${totalProgress}: Install V2Ray"

	if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
		if [[ "${selectCoreType}" == "2" ]]; then

			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[].tag_name | head -1)
		else
			version=${v2rayCoreVersion}
		be

		echoContent green "---> v2ray-core version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		be

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
	else
		if [[ "${selectCoreType}" == "3" ]]; then
			echoContent green "---> lock v2ray-core version to v4.32.1"
			rm -f /etc/v2ray-agent/v2ray/v2ray
			rm -f /etc/v2ray-agent/v2ray/v2ctl
			installV2Ray "$1"
		else
			echoContent green " ---> v2ray-core版本:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
			read -r -p "Do you want to update or upgrade? [y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				installV2Ray "$1"
			be
		be
	be
}

# Install xray
installXray() {
	readInstallType
	echoContent skyBlue "\nProgress$1/${totalProgress}: Install Xray"

	if [[ "${coreInstallType}" != "1" ]]; then

		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -1)

		echoContent green "---> Xray-core version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		be

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
	else
		echoContent green " ---> Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
		read -r -p "Do you want to update or upgrade? [y/n]:" reInstallXrayStatus
		if [[ "${reInstallXrayStatus}" == "y" ]]; then
			rm -f /etc/v2ray-agent/xray/xray
			installXray "$1"
		be
	be
}

#Axic Trojan-go
installTrojanGo () {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Install Trojan-Go"
	if [[ -z $(find /etc/v2ray-agent/trojan/ -name "trojan-go") ]]; then

		version=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases | jq -r .[0].tag_name)
		echoContent green "---> Trojan-Go version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/trojan/ "https://github.com/p4gefau1t/trojan-go/releases/download/${version}/${trojanGoCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/trojan/ "https://github.com/p4gefau1t/trojan-go/releases/download/${version}/${trojanGoCPUVendor}.zip" >/dev/null 2>&1
		be
		unzip -o "/etc/v2ray-agent/trojan/${trojanGoCPUVendor}.zip" -d /etc/v2ray-agent/trojan >/dev/null
		rm -rf "/etc/v2ray-agent/trojan/${trojanGoCPUVendor}.zip"
	else
		echoContent green " ---> Trojan-Go版本:$(/etc/v2ray-agent/trojan/trojan-go --version | awk '{print $2}' | head -1)"

		read -r -p "Do you want to reinstall? [y/n]:" reInstallTrojanStatus
		if [[ "${reInstallTrojanStatus}" == "y" ]]; then
			rm -rf /etc/v2ray-agent/trojan/trojan-go*
			installTrojanGo "$1"
		be
	be
}

# v2ray version management
v2rayVersionManageMenu() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: V2Ray version management"
	if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
		echoContent red "---> The installation directory is not detected, please execute the script to install the content"
		menu
		exit 0
	be
	echoContent red "\n=============================================================="
	echoContent yellow "1. Upgrade"
	echoContent yellow "2.回退"
	echoContent yellow "3. Turn off v2ray-core"
	echoContent yellow "4. Open v2ray-core"
	echoContent yellow "5. Restart v2ray-core"
	echoContent red "=============================================================="
	read -r -p "Please select:" selectV2RayType
	if [[ "${selectV2RayType}" == "1" ]]; then
		updateV2Ray
	elif [[ "${selectV2RayType}" == "2" ]]; then
		echoContent yellow "\n1. Only the last five versions can be rolled back"
		echoContent yellow "2. There is no guarantee that it can be used normally after the rollback"
		echoContent yellow "3. If the rolled back version does not support the current config, you will not be able to connect, please operate with caution"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[].tag_name | head -5 | awk '{print ""NR""":"$0}'

		echoContent skyBlue "--------------------------------------------------------------"
		read -r -p "Please enter the version to be rolled back:" selectV2rayVersionType
		version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[].tag_name | head -5 | awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateV2Ray "${version}"
		else
			echoContent red "\n ---> The input is wrong, please re-enter"
			v2rayVersionManageMenu 1
		be
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleV2Ray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleV2Ray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	be
}

# xray version management
xrayVersionManageMenu () {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Xray version management"
	if [[ ! -d "/etc/v2ray-agent/xray/" ]]; then
		echoContent red "---> The installation directory is not detected, please execute the script to install the content"
		menu
		exit 0
	be
	echoContent red "\n=============================================================="
	echoContent yellow "1. Upgrade"
	echoContent yellow "2.回退"
	echoContent yellow "3. Close Xray-core"
	echoContent yellow "4. Open Xray-core"
	echoContent yellow "5. Restart Xray-core"
	echoContent red "=============================================================="
	read -r -p "Please select:" selectXrayType
	if [[ "${selectXrayType}" == "1" ]]; then
		updateXray
	elif [[ "${selectXrayType}" == "2" ]]; then
		echoContent yellow "\n1. Due to frequent updates of Xray-core, only the latest two versions can be rolled back"
		echoContent yellow "2. There is no guarantee that it can be used normally after the rollback"
		echoContent yellow "3. If the rolled back version does not support the current config, you will not be able to connect, please operate with caution"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -2 | awk '{print ""NR""":"$0}'
		echoContent skyBlue "--------------------------------------------------------------"
		read -r -p "Please enter the version to be rolled back:" selectXrayVersionType
		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -2 | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateXray "${version}"
		else
			echoContent red "\n ---> The input is wrong, please re-enter"
			xrayVersionManageMenu 1
		be
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleXray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleXray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	be

}
# Update V2Ray
updateV2Ray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[0].tag_name)
		be
		# Use locked version
		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		be
		echoContent green "---> v2ray-core version: ${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P "/etc/v2ray-agent/v2ray/ https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		be

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
		handleV2Ray stop
		handleV2Ray start
	else
		echoContent green "---> current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk'{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r .[0].tag_name)
		be

		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		be
		if [[ -n "$1" ]]; then
			read -r -p "The rollback version is ${version}, do you want to continue? [y/n]:" rollbackV2RayStatus
			if [[ "${rollbackV2RayStatus}" == "y" ]]; then
				if [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
					echoContent green "---> current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk'{print $2}' | head -1)"
				elif [[ "${coreInstallType}" == "1" ]]; then
					echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
				be

				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray "${version}"
			else
				echoContent green "---> Abandon the fallback version"
			be
		elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "The current version is the same as the latest version. Do you want to reinstall? [y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green "---> abandon reinstallation"
			be
		else
			read -r -p "The latest version is: ${version}, do you want to update? [y/n]:" installV2RayStatus
			if [[ "${installV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green "---> abandon update"
			be

		be
	be
}

# Update Xray
updateXray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then
		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		be

		echoContent green "---> Xray-core version: ${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		be

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
		handleXray stop
		handleXray start
	else
		echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		be

		if [[ -n "$1" ]]; then
			read -r -p "The rollback version is ${version}, do you want to continue? [y/n]:" rollbackXrayStatus
			if [[ "${rollbackXrayStatus}" == "y" ]]; then
				echoContent green " ---> 当前Xray-core版本:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				updateXray "${version}"
			else
				echoContent green "---> Abandon the fallback version"
			be
		elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "The current version is the same as the latest version. Do you want to reinstall? [y/n]:" reInstallXrayStatus
			if [[ "${reInstallXrayStatus}" == "y" ]]; then
				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green "---> abandon reinstallation"
			be
		else
			read -r -p "The latest version is: ${version}, do you want to update? [y/n]:" installXrayStatus
			if [[ "${installXrayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green "---> abandon update"
			be

		be
	be
}

# Verify that the entire service is available
checkGFWStatue () {
	readInstallType
	echoContent skyBlue "\nProgress $1/${totalProgress}: verify service startup status"
	if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f xray/xray) ]]; then
		echoContent green "---> The service started successfully"
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]] && [[ -n $(pgrep -f v2ray/v2ray) ]]; then
		echoContent green "---> The service started successfully"
	else
		echoContent red "---> The service failed to start, please check whether there is log printing on the terminal"
		exit 0
	be

}

# V2Ray starts automatically after booting
installV2RayService() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Configure V2Ray to start automatically after booting"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/v2ray.service
		touch /etc/systemd/system/v2ray.service
		execStart='/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf'
		cat <<EOF >/etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray - A unified platform for anti-censorship
Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable v2ray.service
		echoContent green "---> Configure V2Ray to start successfully after booting"
	be
}

# Xray boot from start
installXrayService() {
	echoContent skyBlue "\nProgress $1/${totalProgress}: Configure Xray to start automatically after booting"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/xray.service
		touch /etc/systemd/system/xray.service
		execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
		cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray - A unified platform for anti-censorship
# Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable xray.service
		echoContent green "---> Configure Xray to start successfully after booting"
	be
}
# Trojan boot from start
installTrojanService() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Configure Trojan to start automatically after booting"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/trojan-go.service
		touch /etc/systemd/system/trojan-go.service

		cat <<EOF >/etc/systemd/system/trojan-go.service
[Unit]
Description=Trojan-Go - A unified platform for anti-censorship
Documentation=Trojan-Go
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=/etc/v2ray-agent/trojan/trojan-go -config /etc/v2ray-agent/trojan/config_full.json
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable trojan-go.service
		echoContent green "---> Configure Trojan to start successfully after booting"
	be
}
# Operate V2Ray
handleV2Ray () {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q v2ray.service; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "start" ]]; then
			systemctl start v2ray.service
		elif [[ -n $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop v2ray.service
		be
	be
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green "---> V2Ray started successfully"
		else
			echoContent red "V2Ray failed to start"
			echoContent red "Please manually execute [/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf] to check the error log"
			exit 0
		be
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green "---> V2Ray closed successfully"
		else
			echoContent red "V2Ray failed to close"
			echoContent red "Please manually execute [ps -ef|grep -v grep|grep v2ray|awk'{print \$2}'|xargs kill -9]"
			exit 0
		be
	be
}
# Operation xray
handleXray() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/ -name "xray.service") ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
			systemctl start xray.service
		elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop xray.service
		be
	be

	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "xray/xray") ]]; then
			echoContent green "---> Xray started successfully"
		else
			echoContent red "xray failed to start"
			echoContent red "Please manually execute [/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf] to check the error log"
			exit 0
		be
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]]; then
			echoContent green "---> Xray closed successfully"
		else
			echoContent red "xray shutdown failed"
			echoContent red "Please manually execute [ps -ef|grep -v grep|grep xray|awk'{print \$2}'|xargs kill -9]"
			exit 0
		be
	be
}

# Initialize the V2Ray configuration file
initV2RayConfig() {
	echoContent skyBlue "\nProgress$2/${totalProgress}: Initialize V2Ray configuration"
	echo

	read -r -p "Do you want to customize UUID? [y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter a valid UUID:" currentCustomUUID
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		be
	be

	if [[ -n "${currentUUID}" && -z "${uuid}" ]]; then
		read -r -p "Read the last installation record, whether to use the UUID of the last installation? [y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
		else
			uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
		be
	elif [[ -z "${uuid}" ]]; then
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	be

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ---> uuid read error, regenerate"
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	be

	rm -rf /etc/v2ray-agent/v2ray/conf/*
	rm -rf /etc/v2ray-agent/v2ray/config_full.json

	cat <<EOF >/etc/v2ray-agent/v2ray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/v2ray/error.log",
    "loglevel": "warning"
  }
}
EOF
	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF
	else

		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	be

	# dns
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF
	# VLESS_TCP_TLS/XTLS
	# Back down nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_trojan_tcp"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	be

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}_VLESS_WS"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	be

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_vmess_ws"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	be
	# VLESS gRPC
	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
        			"email": "${domain}_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
	be

	# VLESS_TCP
	if [[ "${selectCoreType}" == "2" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
  "inbounds":[
    {
      "port": 443,
      "protocol": "vless",
      "tag":"VLESSTCP",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "add": "${add}",
            "email": "${domain}_VLESS_TLS_TCP"
          }
        ],
        "decryption": "none",
        "fallbacks": [
        	${fallbacksList}
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": [
            "http/1.1",
            "h2"
          ],
          "certificates": [
            {
              "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
              "keyFile": "/etc/v2ray-agent/tls/${domain}.key"
            }
          ]
        }
      }
    }
  ]
}
EOF
	elif [[ "${selectCoreType}" == "3" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}_VLESS_XTLS/TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "alpn": [
        "http/1.1"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key"
        }
      ]
    }
  }
}
]
}
EOF
	be
}

# Initialize the Xray Trojan XTLS configuration file
initXrayFrontingConfig() {
	if [[ -z "${configPath}" ]]; then
		echoContent red "---> not installed, please use script to install"
		menu
		exit 0
	be
	if [[ "${coreInstallType}" != "1" ]]; then
		echoContent red "---> available types are not installed"
	be
	local xtlsType=
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		xtlsType=VLESS
	else
		xtlsType=Trojan

	be

	echoContent skyBlue "\nFunction 1/${totalProgress}: Switch to ${xtlsType} beforehand"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "will replace the prefix with ${xtlsType}"
	echoContent yellow "If the front is Trojan, two Trojan protocol nodes will appear when viewing the account, one of which is unavailable xtls"
	echoContent yellow "Execute again to switch to the previous front\n"

	echoContent yellow "1. Switch to ${xtlsType}"
	echoContent red "=============================================================="
	read -r -p "Please select:" selectType
	if [[ "${selectType}" == "1" ]]; then

		if [[ "${xtlsType}" == "Trojan" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}${frontingType}.json)
			VLESSConfig=${VLESSConfig//"id"/"password"}
			VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
			VLESSConfig=${VLESSConfig//VLESS/Trojan}
			VLESSConfig=${VLESSConfig//"vless"/"trojan"}
			VLESSConfig=${VLESSConfig//"id"/"password"}

			echo "${VLESSConfig}" | jq . >${configPath}02_trojan_TCP_inbounds.json
			rm ${configPath}${frontingType}.json
		elif [[ "${xtlsType}" == "VLESS" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
			VLESSConfig=${VLESSConfig//"password"/"id"}
			VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
			VLESSConfig=${VLESSConfig//Trojan/VLESS}
			VLESSConfig=${VLESSConfig//"trojan"/"vless"}
			VLESSConfig=${VLESSConfig//"password"/"id"}

			echo "${VLESSConfig}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
			rm ${configPath}02_trojan_TCP_inbounds.json
		be
		reloadCore
	be

	exit 0
}

# Initialize the Xray configuration file
initXrayConfig() {
	echoContent skyBlue "\nProgress$2/${totalProgress}: Initialize Xray configuration"
	echo
	local uuid=
	if [[ -n "${currentUUID}" ]]; then
		read -r -p "Read the last installation record, whether to use the UUID of the last installation? [y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
			echoContent green "\n ---> Successfully used"
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		be
	be

	if [[ -z "${uuid}" ]]; then
		echoContent yellow "Please enter a custom UUID[Required Legal], [Enter] Random UUID"
		read -r -p 'UUID:' customUUID

		if [[ -n ${customUUID} ]]; then
			uuid=${customUUID}
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		be

	be

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ---> uuid read error, regenerate"
		uuid=$(/etc/v2ray-agent/xray/xray uuid)
	be

	echoContent yellow "\n ${uuid}"

	rm -rf /etc/v2ray-agent/xray/conf/*

	# log
	cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning"
  }
}
EOF

	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	be

	# dns
	cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS/XTLS
	# Back down nginx
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_trojan_tcp"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	be

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}_VLESS_WS"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	be

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
			fallbacksList=${fallbacksList//31302/31304}
		be

		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}_trojan_gRPC"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
	be

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_vmess_ws"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	be

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
	be

	# VLESS_TCP
	cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}_VLESS_XTLS/TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
}

# Initialize Trojan-Go configuration
initTrojanGoConfig() {

	echoContent skyBlue "\nProgress$1/${totalProgress}: Initialize Trojan configuration"
	cat <<EOF >/etc/v2ray-agent/trojan/config_full.json
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 31296,
    "remote_addr": "127.0.0.1",
    "remote_port": 31300,
    "disable_http_check":true,
    "log_level":3,
    "log_file":"/etc/v2ray-agent/trojan/trojan.log",
    "password": [
        "${uuid}"
    ],
    "dns":[
        "localhost"
    ],
    "transport_plugin":{
        "enabled":true,
        "type":"plaintext"
    },
    "websocket": {
        "enabled": true,
        "path": "/${customPath}tws",
        "host": "${domain}",
        "add":"${add}"
    },
    "router": {
        "enabled": false
    }
}
EOF
}

# Custom CDN IP
customCDNIP() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: add cloudflare optional CNAME"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions"
	echoContent yellow "\nTutorial address:"
	echoContent skyBlue "https://github.com/mack-a/v2ray-agent/blob/master/documents/optimize_V2Ray.md"
	echoContent red "\nIf you do not understand Cloudflare optimization, please do not use"
	echoContent yellow "\n 1. Move: 104.16.123.96"
	echoContent yellow "2. Unicom: www.cloudflare.com"
	echoContent yellow "3. Telecom: www.digitalocean.com"
	echoContent skyBlue "----------------------------"
	read -r -p "Please select [Enter not to use]:" selectCloudflareType
	case ${selectCloudflareType} in
	1)
		add="104.16.123.96"
		;;
	2)
		add="www.cloudflare.com"
		;;
	3)
		add="www.digitalocean.com"
		;;
	*)
		add="${domain}"
		echoContent yellow "\n ---> not used"
		;;
	esac
}
# General
defaultBase64Code() {
	local type=$1
	local email=$2
	local id=$3
	local hostPort=$4
	local host=
	local port=
	if echo "${hostPort}" | grep -q ":"; then
		host=$(echo "${hostPort}" | awk -F "[:]" '{print $1}')
		port=$(echo "${hostPort}" | awk -F "[:]" '{print $2}')
	else
		host=${hostPort}
		port=443
	be

	local path=$5
	local add=$6

	local subAccount
	subAccount=${currentHost}_$(echo "${id}_currentHost" | md5sum | awk '{print $1}')

	if [[ "${type}" == "vlesstcp" ]]; then

		if [[ "${coreInstallType}" == "1" ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
			echoContent yellow "---> General format (VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

			echoContent yellow "---> format plain text (VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "Protocol type: VLESS, address: ${host}, port: ${port}, user ID: ${id}, security: xtls, transmission method: tcp, flow: xtls-rprx-direct, account name: ${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF
			echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-direct%23${email}\n"

			echoContent skyBlue "----------------------------------------------------------------------------------"

			echoContent yellow "---> General format (VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}\n"

			echoContent yellow "---> formatted plaintext (VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "Protocol type: VLESS, address: ${host}, port: ${port}, user ID: ${id}, security: xtls, transmission method: tcp, flow: xtls-rprx-splice, account name: ${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}
EOF
			echoContent yellow " ---> 二维码 VLESS(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-splice%23${email}\n"

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == "3" ]]; then
			echoContent yellow "---> Common format (VLESS+TCP+TLS)"
			echoContent green "    vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}\n"

			echoContent yellow "---> formatted plaintext (VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "Protocol type: VLESS, address: ${host}, port: ${port}, user ID: ${id}, security: tls, transmission method: tcp, account name: ${email}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}
EOF
			echoContent yellow "---> QR code VLESS(VLESS+TCP+TLS)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3a%2f%2f${id}%40${host}%3a${port}%3fsecurity%3dtls%26encryption%3dnone%26host%3d${host}%26headerType%3dnone%26type%3dtcp%23${email}\n"
		be

	elif [[ "${type}" == "trojanTCPXTLS" ]]; then
		echoContent yellow "---> General format (Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

		echoContent yellow "---> format plain text (Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "Protocol type: Trojan, address: ${host}, port: ${port}, user ID: ${id}, security: xtls, transmission method: tcp, flow: xtls-rprx-direct, account name: ${email}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF
		echoContent yellow "---> QR code Trojan(Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-direct%23${email}\n"

		echoContent skyBlue "----------------------------------------------------------------------------------"

		echoContent yellow "---> General format (Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}\n"

		echoContent yellow "---> format plain text (Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "Protocol type: VLESS, address: ${host}, port: ${port}, user ID: ${id}, security: xtls, transmission method: tcp, flow: xtls-rprx-splice, account name: ${email}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email}
EOF
		echoContent yellow "---> QR code Trojan(Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-splice%23${email}\n"

	elif [[ "${type}" == "vmessws" ]]; then
		qrCodeBase64Default=$(echo -n "{\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"none\",\"path\":\"/${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${host}\",\"sni\":\"${host}\"}" | base64 -w 0)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ---> 通用json(VMess+WS+TLS)"
		echoContent green "    {\"port\":${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${host}\",\"sni\":\"${host}\"}\n"
		echoContent yellow "---> general vmess(VMess+WS+TLS) link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"
		echoContent yellow " ---> 二维码 vmess(VMess+WS+TLS)"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vmesstcp" ]]; then

		echoContent red "path:${path}"
		qrCodeBase64Default=$(echo -n "{\"add\":\"${add}\",\"aid\":0,\"host\":\"${host}\",\"id\":\"${id}\",\"net\":\"tcp\",\"path\":\"${path}\",\"port\":${port},\"ps\":\"${email}\",\"scy\":\"none\",\"sni\":\"${host}\",\"tls\":\"tls\",\"v\":2,\"type\":\"http\",\"allowInsecure\":0,\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}" | base64)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ---> 通用json(VMess+TCP+TLS)"
		echoContent green "    {\"port\":'${port}',\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"http\",\"path\":\"${path}\",\"net\":\"http\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"post\",\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}\n"
		echoContent yellow "---> general vmess(VMess+TCP+TLS) link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent yellow "---> QR code vmess(VMess+TCP+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vlessws" ]]; then

		echoContent yellow "---> Common Format (VLESS+WS+TLS)"
		echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}\n"

		echoContent yellow "---> format plain text (VLESS+WS+TLS)"
		echoContent green "Protocol type: VLESS, address: ${add}, fake domain name/SNI: ${host}, port: ${port}, user ID: ${id}, security: tls, transmission method: ws, path :/${path}, account name: ${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}
EOF

		echoContent yellow "---> QR code VLESS(VLESS+TCP+TLS/XTLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${host}%26sni%3D${host}%26path%3D%252f${path}%23${email}"

	elif [[ "${type}" == "vlessgrpc" ]]; then

		echoContent yellow "---> General Format (VLESS+gRPC+TLS)"
		echoContent green "    vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}\n"

		echoContent yellow "---> formatted plaintext (VLESS+gRPC+TLS)"
		echoContent green "Protocol type: VLESS, address: ${add}, fake domain name/SNI: ${host}, port: ${port}, user ID: ${id}, security: tls, transmission mode: gRPC, alpn : H2, serviceName: ${path}, account name: ${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}:${port}?encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}
EOF
		echoContent yellow "---> QR code VLESS(VLESS+gRPC+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${host}%26serviceName%3D${path}%26path%3D${path}%26sni%3D${host}%26alpn%3Dh2%23${email}"

	elif [[ "${type}" == "trojan" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${host}_Trojan\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${host}_Trojan
EOF
		echoContent yellow "---> QR code Trojan(TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${host}%3a${port}%3fpeer%3d${host}%26sni%3d${host}%26alpn%3Dhttp1.1%23${host}_Trojan\n"

	elif [[ "${type}" == "trojangrpc" ]]; then
		# URLEncode

		echoContent yellow " ---> Trojan gRPC(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${host}_Trojan_gRPC\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${host}_Trojan_gRPC
EOF
		echoContent yellow "---> QR code Trojan gRPC(TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${host}%3a${port}%3Fencryption%3Dnone%26security%3Dtls%26peer%3d${host}%26type%3Dgrpc%26sni%3d${host}%26path%3D${path}%26alpn%3D=h2%26serviceName%3D${path}%23${host}_Trojan_gRPC\n"

	elif [[ "${type}" == "trojangows" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan-Go(WS+TLS) Shadowrocket"
		echoContent green "    trojan://${id}@${add}:${port}?allowInsecure=0&&peer=${host}&sni=${host}&plugin=obfs-local;obfs=websocket;obfs-host=${host};obfs-uri=${path}#${host}_Trojan_ws\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${add}:${port}?allowInsecure=0&&peer=${host}&sni=${host}&plugin=obfs-local;obfs=websocket;obfs-host=${host};obfs-uri=${path}#${host}_Trojan_ws
EOF
		echoContent yellow " ---> 二维码 Trojan-Go(WS+TLS) Shadowrocket"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${add}%3a${port}%3fallowInsecure%3d0%26peer%3d${host}%26plugin%3dobfs-local%3bobfs%3dwebsocket%3bobfs-host%3d${host}%3bobfs-uri%3d${path}%23${host}_Trojan_ws\n"

		path=$(echo "${path}" | awk -F "[/]" '{print $2}')
		echoContent yellow " ---> Trojan-Go(WS+TLS) QV2ray"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan-go://${id}@${add}:${port}?sni=${host}&type=ws&host=${host}&path=%2F${path}#${host}_Trojan_ws
EOF

		echoContent green "    trojan-go://${id}@${add}:${port}?sni=${host}&type=ws&host=${host}&path=%2F${path}#${host}_Trojan_ws\n"

	be

}

# account
showAccounts () {
	readInstallType
	readInstallProtocolType
	readConfigHostPathUUID
	echoContent skyBlue "\nProgress $1/${totalProgress}: account"
	local show
	# VLESS TCP
	if [[ -n "${configPath}" ]]; then
		show=1
		if echo "${currentInstallProtocolType}" | grep -q trojan; then
			echoContent skyBlue "===================== Trojan TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
				echo
				defaultBase64Code trojanTCPXTLS "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)" "${currentHost}:${currentPort}" "${currentHost}"
			done

		else
			echoContent skyBlue "===================== VLESS TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlesstcp "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${currentHost}"
			done
		be

		# VLESS WS
		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent skyBlue "\n================================ VLESS WS TLS CDN ================================\n"

			jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				local path="${currentPath}ws"
				if [[ ${coreInstallType} == "1" ]]; then
					echoContent yellow "There will be ?ed=2048 behind the 0-RTT path of Xray, which is not compatible with the client with v2ray as the core. Please manually delete?ed=2048 and use\n"
					path="${currentPath}ws?ed=2048"
				be
				defaultBase64Code vlessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		be

		# VMess WS
		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent skyBlue "\n================================ VMess WS TLS CDN ================================\n"
			local path="${currentPath}vws"
			if [[ ${coreInstallType} == "1" ]]; then
				path="${currentPath}vws?ed=2048"
			be
			jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vmessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		be

		# VLESS grpc
		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent skyBlue "\n=============================== VLESS gRPC TLS CDN ===============================\n"
			echoContent red "\n --->gRPC is currently in the testing phase and may not be compatible with the client you are using. If you cannot use it, please ignore it."
			local serviceName
			serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}06_VLESS_gRPC_inbounds.json)
			jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlessgrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${serviceName}" "${currentAdd}"
			done
		be
	be

	# trojan tcp
	if echo ${currentInstallProtocolType} | grep -q 4; then
		echoContent skyBlue "\n==================================  Trojan TLS  ==================================\n"
		jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojan trojan "$(echo "${user}" | jq -r .password)" "${currentHost}"
		done
	be

	if echo ${currentInstallProtocolType} | grep -q 2; then
		echoContent skyBlue "\n================================  Trojan gRPC TLS  ================================\n"
		echoContent red "\n --->gRPC is currently in the testing phase and may not be compatible with the client you are using. If you cannot use it, please ignore it."
		local serviceName=
		serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}04_trojan_gRPC_inbounds.json)
		jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> 帐号：$(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojangrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)" "${currentHost}:${currentPort}" "${serviceName}" "${currentAdd}"
		done
	be

	if [[ -z ${show} ]]; then
		echoContent red "---> not installed"
	be
}

# Update camouflage station
updateNginxBlog() {
	echoContent skyBlue "\nProgress $1/${totalProgress}: Replace the fake site"
	echoContent red "=============================================================="
	echoContent yellow "# For customization, please manually copy the template file to /usr/share/nginx/html \n"
	echoContent yellow "1. Novice Guide"
	echoContent yellow "2. Game website"
	echoContent yellow "3. Personal blog 01"
	echoContent yellow "4. Enterprise Station"
	echoContent yellow "5. Unlock the encrypted music file template [https://github.com/ix64/unlock-music]"
	echoContent yellow "6.mikutap[https://github.com/HFIProgramming/mikutap]"
	echoContent yellow "7. Enterprise Station 02"
	echoContent yellow "8. Personal blog 02"
	echoContent yellow "9.404 automatically jump to baidu"
	echoContent red "=============================================================="
	read -r -p "Please select:" selectInstallNginxBlogType

	if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
		#		rm -rf /usr/share/nginx/html
		rm -rf /usr/share/nginx/*
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /usr/share/nginx "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		else
			wget -c -P /usr/share/nginx "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		be

		unzip -o "/usr/share/nginx/html${selectInstallNginxBlogType}.zip" -d /usr/share/nginx/html >/dev/null
		rm -f "/usr/share/nginx/html${selectInstallNginxBlogType}.zip*"
		echoContent green "---> Replace the pseudo site successfully"
	else
		echoContent red "---> wrong selection, please select again"
		updateNginxBlog
	be
}

# Add new port
addCorePort() {
	echoContent skyBlue "\nFunction 1/${totalProgress}: add new port"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "support batch add"
	echoContent yellow "Does not affect the use of port 443"
	echoContent yellow "When viewing accounts, only accounts with default port 443 will be displayed"
	echoContent yellow "Special characters are not allowed, pay attention to the comma format"
	echoContent yellow "Entry example: 2053, 2083, 2087\n"

	echoContent yellow "1. Add port"
	echoContent yellow "2. Delete port"
	echoContent red "=============================================================="
	read -r -p "Please select:" selectNewPortType
	if [[ "${selectNewPortType}" == "1" ]]; then
		read -r -p "Please enter the port number:" newPort
		if [[ -n "${newPort}" ]]; then

			while read -r port; do
				cat <<EOF >"${configPath}02_dokodemodoor_inbounds_${port}.json"
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "tag": "dokodemo-door-newPort-${port}"
    }
  ]
}
EOF
			done < <(echo "${newPort}" | tr ',' '\n')

			echoContent green "---> added successfully"
			reloadCore
		be
	elif [[ "${selectNewPortType}" == "2" ]]; then

		find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}'
		read -r -p "Please enter the port number to be deleted:" portIndex
		local dokoConfig
		dokoConfig=$(find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}' | grep "${portIndex}:")
		if [[ -n "${dokoConfig}" ]]; then
			rm "${configPath}/$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}')"
			reloadCore
		else
			echoContent yellow "\n ---> The number is entered incorrectly, please select again"
			addCorePort
		be
	be
}

# Uninstall script
unInstall() {
	read -r -p "Are you sure to uninstall the installation content? [y/n]:" unInstallStatus
	if [[ "${unInstallStatus}" != "y" ]]; then
		echoContent green "---> abandon uninstall"
		menu
		exit 0
	be

	handleNginx stop
	if [[ -z $(pgrep -f "nginx") ]]; then
		echoContent green "---> Stop Nginx successfully"
	be

	handleV2Ray stop
	#	handleTrojanGo stop
	rm -rf /root/.acme.sh
	echoContent green "---> delete acme.sh complete"
	rm -rf /etc/systemd/system/v2ray.service
	echoContent green "---> Delete V2Ray boot and self-start complete"

	rm -rf /etc/systemd/system/trojan-go.service
	echoContent green "---> Delete Trojan-Go to complete after booting up"
	rm -rf /tmp/v2ray-agent-tls/*
	if [[ -d "/etc/v2ray-agent/tls" ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.key") ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.crt") ]]; then
		mv /etc/v2ray-agent/tls /tmp/v2ray-agent-tls
		if [[ -n $(find /tmp/v2ray-agent-tls -name '*.key') ]]; then
			echoContent yellow "---> The backup certificate is successful, please keep it. [/tmp/v2ray-agent-tls]"
		be
	be

	rm -rf /etc/v2ray-agent
	rm -rf /etc/nginx/conf.d/alone.conf
	rm -rf /usr/bin/vasma
	rm -rf /usr/sbin/vasma
	echoContent green "---> uninstall shortcut completed"
	echoContent green "---> uninstall v2ray-agent script completed"
}

# Modify V2Ray CDN node
updateV2RayCDN() {

	# todo Refactor this method
	echoContent skyBlue "\nProgress$1/${totalProgress}: modify CDN node"

	if [[ -n "${currentAdd}" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "1.CNAME www.digitalocean.com"
		echoContent yellow "2.CNAME www.cloudflare.com"
		echoContent yellow "3.CNAME hostmonit.com"
		echoContent yellow "4. Manual input"
		echoContent red "=============================================================="
		read -r -p "Please select:" selectCDNType
		case ${selectCDNType} in
		1)
			setDomain="www.digitalocean.com"
			;;
		2)
			setDomain="www.cloudflare.com"
			;;
		3)
			setDomain="hostmonit.com"
			;;
		4)
			read -r -p "Please enter the CDN IP or domain name you want to customize:" setDomain
			;;
		esac

		if [[ -n ${setDomain} ]]; then
			if [[ -n "${currentAdd}" ]]; then
				sed -i "s/\"${currentAdd}\"/\"${setDomain}\"/g" "$(grep "${currentAdd}" -rl ${configPath}${frontingType}.json)"
			be
			if [[ $(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json) == "${setDomain}" ]]; then
				echoContent green "---> CDN modified successfully"
				reloadCore
			else
				echoContent red "---> Failed to modify CDN"
			be
		be
	else
		echoContent red "---> available types are not installed"
	be
}

# manageUser User Management
manageUser() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: Multi-user management"
	echoContent skyBlue "-----------------------------------------------------"
	echoContent yellow "1. Add user"
	echoContent yellow "2. Delete user"
	echoContent skyBlue "-----------------------------------------------------"
	read -r -p "Please select:" manageUserType
	if [[ "${manageUserType}" == "1" ]]; then
		addUser
	elif [[ "${manageUserType}" == "2" ]]; then
		removeUser
	else
		echoContent red "---> wrong selection"
	be
}

# Custom uuid
customUUID() {
	read -r -p "Do you want to customize UUID? [y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter a valid UUID:" currentCustomUUID
		echo
		if [[ -z "${currentCustomUUID}" ]]; then
			echoContent red "---> UUID cannot be empty"
		else
			jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomUUID}" ]]; then
					echo >/tmp/v2ray-agent
				be
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red "---> UUID cannot be repeated"
				rm /tmp/v2ray-agent
				exit 0
			be
		be
	be
}

# Custom email
customUserEmail() {
	read -r -p "Do you want to customize email? [y/n]:" customEmailStatus
	echo
	if [[ "${customEmailStatus}" == "y" ]]; then
		read -r -p "Please enter a valid email:" currentCustomEmail
		echo
		if [[ -z "${currentCustomEmail}" ]]; then
			echoContent red "---> email cannot be empty"
		else
			jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomEmail}" ]]; then
					echo >/tmp/v2ray-agent
				be
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red "---> email cannot be repeated"
				rm /tmp/v2ray-agent
				exit 0
			be
		be
	be
}

# Add user
addUser() {

	echoContent yellow "After adding a new user, you need to check the subscription again"
	read -r -p "Please enter the number of users to be added:" userNum
	echo
	if [[-z $ {userNum} || $ {userNum} -le 0]]; then
		echoContent red "---> The input is wrong, please re-enter"
		exit 0
	be

	# Generate users
	if [[ "${userNum}" == "1" ]]; then
		customUUID
		customUserEmail
	be

	while [[$ {userNum} -gt 0]]; do
		local users=
		((userNum--)) || true
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		else
			uuid=$(${ctlPath} uuid)
		be

		if [[ -n "${currentCustomEmail}" ]]; then
			email=${currentCustomEmail}
		else
			email=${currentHost}_${uuid}
		be

		# Compatible with v2ray-core
		users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"alterId\":0}"

		if [[ "${coreInstallType}" == "2" ]]; then
			users="{\"id\":\"${uuid}\",\"email\":\"${email}\",\"alterId\":0}"
		be

		if echo ${currentInstallProtocolType} | grep -q 0; then
			local vlessUsers="${users//\,\"alterId\":0/}"

			local vlessTcpResult
			vlessTcpResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		be

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			local trojanXTLSUsers="${users//\,\"alterId\":0/}"
			trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}

			local trojanXTLSResult
			trojanXTLSResult=$(jq -r ".inbounds[0].settings.clients += [${trojanXTLSUsers}]" ${configPath}${frontingType}.json)
			echo "${trojanXTLSResult}" | jq . >${configPath}${frontingType}.json
		be

		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessUsers="${users//\,\"alterId\":0/}"
			vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-direct\"\,/}"
			local vlessWsResult
			vlessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWsResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
			trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

			local trojangRPCResult
			trojangRPCResult=$(jq -r ".inbounds[0].settings.clients += [${trojangRPCUsers}]" ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCResult}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"

			local vmessWsResult
			vmessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vmessUsers}]" ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWsResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"

			local vlessGRPCResult
			vlessGRPCResult=$(jq -r ".inbounds[0].settings.clients += [${vlessGRPCUsers}]" ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojanUsers="${trojanUsers//id/password}"
			trojanUsers="${trojanUsers//\,\"alterId\":0/}"

			local trojanTCPResult
			trojanTCPResult=$(jq -r ".inbounds[0].settings.clients += [${trojanUsers}]" ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		be
	done

	reloadCore
	echoContent green "---> add complete"
	showAccounts 1
}

# Remove user
removeUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		read -r -p "Please select the user number to be deleted [only single deletion is supported]:" delUserIndex
		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red "---> wrong selection"
		else
			delUserIndex = $ ((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		be
	be
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		be

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		be

		reloadCore
	be
	manageAccount 1
}
# Update script
updateV2RayAgent() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: update v2ray-agent script"
	rm -rf /etc/v2ray-agent/install.sh
	if wget --help | grep -q show-progress; then
		wget -c -q --show-progress -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
	else
		wget -c -q -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
	be

	sudo chmod 700 /etc/v2ray-agent/install.sh
	local version
	version=$(grep '当前版本：v' "/etc/v2ray-agent/install.sh" | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')

	echoContent green "\n ---> update complete"
	echoContent yellow "---> Please manually execute [vasma] to open the script"
	echoContent green "---> current version: ${version}\n"
	echoContent yellow "If the update is not successful, please execute the following command manually\n"
	echoContent skyBlue "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
	echo
	exit 0
}

# Firewall
handleFirewall() {
	if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
		systemctl stop ufw >/dev/null 2>&1
		systemctl disable ufw >/dev/null 2>&1
		echoContent green "---> ufw closed successfully"

	be

	if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
		systemctl stop firewalld >/dev/null 2>&1
		systemctl disable firewalld >/dev/null 2>&1
		echoContent green "---> firewalld closed successfully"
	be
}

# Install BBR
bbrInstall() {
	echoContent red "\n=============================================================="
	echoContent green "Mature works of [ylx2016] used by BBR and DD scripts, address [https://github.com/ylx2016/Linux-NetSpeed], please be familiar with"
	echoContent yellow "1. Installation script [Recommend original BBR+FQ]"
	echoContent yellow "2. Back to home directory"
	echoContent red "=============================================================="
	read -r -p "Please choose:" installBBRStatus
	if [[ "${installBBRStatus}" == "1" ]]; then
		wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
	else
		menu
	be
}

# View and check logs
checkLog() {
	if [[ -z ${configPath} ]]; then
		echoContent red "---> The installation directory is not detected, please execute the script to install the content"
	be
	local logStatus=false
	if grep -q "access" ${configPath}00_log.json; then
		logStatus=true
	be

	echoContent skyBlue "\nFunction $1/${totalProgress}: View log"
	echoContent red "\n=============================================================="
	echoContent yellow "# It is recommended to open the access log only when debugging\n"

	if [[ "${logStatus}" == "false" ]]; then
		echoContent yellow "1. Open access log"
	else
		echoContent yellow "1. Close access log"
	be

	echoContent yellow "2. Monitor access log"
	echoContent yellow "3. Monitor error log"
	echoContent yellow "4. View certificate timing task log"
	echoContent yellow "5. View the certificate installation log"
	echoContent yellow "6. Clear log"
	echoContent red "=============================================================="

	read -r -p "Please select:" selectAccessLogType
	local configPathLog=${configPath//conf\//}

	case ${selectAccessLogType} in
	1)
		if [[ "${logStatus}" == "false" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
		elif [[ "${logStatus}" == "true" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
		be
		reloadCore
		checkLog 1
		;;
	2)
		tail -f ${configPathLog}access.log
		;;
	3)
		tail -f ${configPathLog}error.log
		;;
	4)
		tail -n 100 /etc/v2ray-agent/crontab_tls.log
		;;
	5)
		tail -n 100 /etc/v2ray-agent/tls/acme.log
		;;
	6)
		echo >${configPathLog}access.log
		echo >${configPathLog}error.log
		;;
	esac
}

# Script shortcut
aliasInstall() {

	if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <"$HOME/install.sh" -q "作者：mack-a"; then
		mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
		local vasmaType=
		if [[ -d "/usr/bin/" ]]; then
			if [[ ! -f "/usr/bin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh / usr / bin / vasma
				chmod 700 / usr / bin / vasma
				vasmaType=true
			be

			rm -rf "$HOME/install.sh"
		elif [[ -d "/usr/sbin" ]]; then
			if [[ ! -f "/usr/sbin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh / usr / sbin / vasma
				chmod 700 / usr / sbin / vasma
				vasmaType=true
			be
			rm -rf "$HOME/install.sh"
		be
		if [[ "${vasmaType}" == "true" ]]; then
			echoContent green "The shortcut is successfully created, and the script can be reopened by executing [vasma]"
		be
	be
}

# Check ipv6, ipv4
checkIPv6() {
	pingIPv6=$(ping6 -c 1 www.google.com | sed '2{s/[^(]*(//;s/).*//;q;}' | tail -n +2)
	if [[ -z "${pingIPv6}" ]]; then
		echoContent red "---> ipv6 is not supported"
		exit 0
	be
}

# ipv6 Shunt
ipv6Routing() {
	if [[ -z "${configPath}" ]]; then
		echoContent red "---> not installed, please use script to install"
		menu
		exit 0
	be

	checkIPv6
	echoContent skyBlue "\nFunction 1/${totalProgress}: IPv6 offload"
	echoContent red "\n=============================================================="
	echoContent yellow "1. Add domain name"
	echoContent yellow "2. Uninstall IPv6 offloading"
	echoContent red "=============================================================="
	read -r -p "Please select:" ipv6Status
	if [[ "${ipv6Status}" == "1" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1. The rule only supports a list of predefined domain names [https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2. Detailed documentation [https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3. If the kernel fails to start, please check the domain name and re-add the domain name"
		echoContent yellow "4. Special characters are not allowed, pay attention to the comma format"
		echoContent yellow "5. Every time you add it is added again, the last domain name will not be retained"
		echoContent yellow "6. Input example: google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting IPv6-out

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"IPv6-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >"${configPath}09_routing.json"
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "IPv6-out"
          }
        ]
  }
}
EOF
		be

		unInstallOutbounds IPv6-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"},"tag":"IPv6-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green "---> added successfully"

	elif [[ "${ipv6Status}" == "2" ]]; then

		unInstallRouting IPv6-out

		unInstallOutbounds IPv6-out

		echoContent green "---> IPv6 offloading offload successfully"
	else
		echoContent red "---> wrong selection"
		exit 0
	be

	reloadCore
}

# bt download management
btTools() {
	if [[ -z "${configPath}" ]]; then
		echoContent red "---> not installed, please use script to install"
		menu
		exit 0
	be

	echoContent skyBlue "\nFunction1/${totalProgress}: bt download management"
	echoContent red "\n=============================================================="

	if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent <${configPath}09_routing.json; then
		echoContent yellow "Current status: disabled"
	else
		echoContent yellow "Current status: not disabled"
	be

	echoContent yellow "1. Disabled"
	echoContent yellow "2. Open"
	echoContent red "=============================================================="
	read -r -p "Please select:" btStatus
	if [[ "${btStatus}" == "1" ]]; then

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting blackhole-out

			routing=$(jq -r '.routing.rules += [{"type":"field","outboundTag":"blackhole-out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole-out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
		be

		installSniffing

		unInstallOutbounds blackhole-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green "---> BT download disabled successfully"

	elif [[ "${btStatus}" == "2" ]]; then

		unInstallSniffing

		unInstallRouting blackhole-out

		unInstallOutbounds blackhole-out

		echoContent green "---> BT download opened successfully"
	else
		echoContent red "---> wrong selection"
		exit 0
	be

	reloadCore
}

# Uninstall Routing according to tag
unInstallRouting() {
	local tag=$1

	if [[ -f "${configPath}09_routing.json" ]]; then
		local routing
		if grep -q "${tag}" ${configPath}09_routing.json; then
			local index
			index=$(jq .routing.rules[].outboundTag ${configPath}09_routing.json | awk '{print ""NR""":"$0}' | grep "${tag}" | awk -F "[:]" '{print $1}' | head -1)
			if [[ ${index} -gt 0 ]]; then
				routing=$(jq -r 'del(.routing.rules['"$(("${index}" - 1))"'])' ${configPath}09_routing.json)
				echo "${routing}" | jq . >${configPath}09_routing.json
			be
		be
	be
}

# Uninstall outbound according to tag
unInstallOutbounds() {
	local tag=$1

	if grep -q "${tag}" ${configPath}10_ipv4_outbounds.json; then
		local ipv6OutIndex
		ipv6OutIndex=$(jq .outbounds[].tag ${configPath}10_ipv4_outbounds.json | awk '{print ""NR""":"$0}' | grep "${tag}" | awk -F "[:]" '{print $1}' | head -1)
		if [[ ${ipv6OutIndex} -gt 0 ]]; then
			routing=$(jq -r 'del(.outbounds['$(("${ipv6OutIndex}" - 1))'])' ${configPath}10_ipv4_outbounds.json)
			echo "${routing}" | jq . >${configPath}10_ipv4_outbounds.json
		be
	be

}

# Uninstall sniffing
unInstallSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
		echo "${sniffing}" | jq . >"${configPath}${inbound}"
	done
}

# Install sniffing
installSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r '.inbounds[0].sniffing = {"enabled":true,"destOverride":["http","tls"]}' "${configPath}${inbound}")
		echo "${sniffing}" | jq . >"${configPath}${inbound}"
	done
}

# warp分流
warpRouting() {
	echoContent skyBlue "\nProgress$1/${totalProgress}: WARP diversion"
	echoContent red "=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "1. The official warp has bugs after several rounds of testing. Restarting will cause the warp to fail and fail to start, and the CPU usage may also skyrocket."
	echoContent yellow "2. It can be used normally without restarting the machine. If you have to use the official warp, it is recommended not to restart the machine."
	echoContent yellow "3. Some machines are still in normal use after restarting"
	echoContent yellow "4. Can not be used after restarting, or uninstall and reinstall"
	# Install warp
	if [[ -z $(which warp-cli) ]]; then
		echo
		read -r -p "WARP is not installed, do you want to install it? [y/n]:" installCloudflareWarpStatus
		if [[ "${installCloudflareWarpStatus}" == "y" ]]; then
			installWarp
		else
			echoContent yellow "---> Abandon installation"
			exit 0
		be
	be

	echoContent red "\n=============================================================="
	echoContent yellow "1. Add domain name"
	echoContent yellow "2. Uninstall WARP offloading"
	echoContent red "=============================================================="
	read -r -p "Please select:" warpStatus
	if [[ "${warpStatus}" == "1" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1. The rule only supports a list of predefined domain names [https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2. Detailed documentation [https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3. Only traffic can be diverted to warp, not ipv4 or ipv6"
		echoContent yellow "4. If the kernel fails to start, please check the domain name and add the domain name again"
		echoContent yellow "5. Special characters are not allowed, pay attention to the comma format"
		echoContent yellow "6. Every time you add it is added again, the last domain name will not be retained"
		echoContent yellow "7. Input example: google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to the example above:" domainList

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting warp-socks-out

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"warp-socks-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "warp-socks-out"
          }
        ]
  }
}
EOF
		be
		unInstallOutbounds warp-socks-out

		local outbounds
		outbounds=$(jq -r '.outbounds += [{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":31303}]},"tag":"warp-socks-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green "---> added successfully"

	elif [[ "${warpStatus}" == "2" ]]; then

		${removeType} cloudflare-warp >/dev/null 2>&1

		unInstallRouting warp-socks-out

		unInstallOutbounds warp-socks-out

		echoContent green "---> WARP offloading succeeded"
	else
		echoContent red "---> wrong selection"
		exit 0
	be
	reloadCore
}
# Streaming Media Toolbox
streamingToolbox() {
	echoContent skyBlue "\nFunction 1/${totalProgress}: Streaming Media Toolbox"
	echoContent red "\n=============================================================="
	# echoContent yellow "1.Netflix detection"
	echoContent yellow "1. Any door landing machine to unblock Netflix"
	echoContent yellow "2.DNS to unlock streaming media"
	read -r -p "Please select:" selectType

	case ${selectType} in
	# 1)
	# checkNetflix
	# ;;
	1)
		dokodemoDoorUnblockNetflix
		;;
	2)
		dnsUnlockNetflix
		;;
	esac

}

# Any door to unlock netflix
dokodemoDoorUnblockNetflix () {
	echoContent skyBlue "\nFunction 1/${totalProgress}: Unlock Netflix at any door landing machine"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions"
	echoContent yellow "For details on unlocking any door, please check this article [https://github.com/mack-a/v2ray-agent/blob/master/documents/netflix/dokodemo-unblock_netflix.md]\n"

	echoContent yellow "1. Add outbound"
	echoContent yellow "2. Add inbound"
	echoContent yellow "3. Uninstall"
	read -r -p "Please select:" selectType

	case ${selectType} in
	1)
		setDokodemoDoorUnblockNetflixOutbounds
		;;
	2)
		setDokodemoDoorUnblockNetflixInbounds
		;;
	3)
		removeDokodemoDoorUnblockNetflix
		;;
	esac
}

# Set any door to unblock Netflix【Outbound】
setDokodemoDoorUnblockNetflixOutbounds() {
	read -r -p "Please enter the IP to unlock Netflix vps:" setIP
	if [[ -n "${setIP}" ]]; then

		unInstallOutbounds netflix-80
		unInstallOutbounds netflix-443

		outbounds=$(jq -r ".outbounds += [{\"tag\":\"netflix-80\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22387\"}},{\"tag\":\"netflix-443\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22388\"}}]" ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting netflix-80
			unInstallRouting netflix-443

			local routing
			routing=$(jq -r '.routing.rules += [{"type":"field","port":80,"domain":["ip.sb","geosite:netflix"],"outboundTag":"netflix-80"},{"type":"field","port":443,"domain":["ip.sb","geosite:netflix"],"outboundTag":"netflix-443"}]' ${configPath}09_routing.json)
			echo "${routing}" | jq . >${configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "port": 80,
        "domain": [
          "ip.sb",
          "geosite:netflix"
        ],
        "outboundTag": "netflix-80"
      },
      {
        "type": "field",
        "port": 443,
        "domain": [
          "ip.sb",
          "geosite:netflix"
        ],
        "outboundTag": "netflix-443"
      }
    ]
  }
}
EOF
		be
		reloadCore
		echoContent green "---> Add Netflix to play and unlock successfully"
		# echoContent yellow "---> Related nodes of trojan are not supported"
		exit 0
	be
	echoContent red "---> ip cannot be empty"
}

# Set any door to unblock Netflix [Inbound]
setDokodemoDoorUnblockNetflixInbounds() {

	echoContent skyBlue "\nFunction1/${totalProgress}: add inbound to any door"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "support batch add"
	echoContent yellow "Special characters are not allowed, pay attention to the comma format"
	echoContent yellow "Input example: 1.1.1.1,1.1.1.2\n"
	read -r -p "Please enter the IP that is allowed to access the unblocked Netflix vps:" setIPs
	if [[ -n "${setIPs}" ]]; then
		cat <<EOF >${configPath}01_netflix_inbounds.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 22387,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 80,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http"
        ]
      },
      "tag": "unblock-80"
    },
    {
      "listen": "0.0.0.0",
      "port": 22388,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "tls"
        ]
      },
      "tag": "unblock-443"
    }
  ]
}
EOF

		cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF

		cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "rules": [
      {
        "source": [],
        "type": "field",
        "inboundTag": [
          "unblock-80",
          "unblock-443"
        ],
        "outboundTag": "direct"
      },
      {
        "domains": [
        	"geosite:netflix"
        ],
        "type": "field",
        "inboundTag": [
          "unblock-80",
          "unblock-443"
        ],
        "outboundTag": "blackhole-out"
      }
    ]
  }
}
EOF

		oldIFS="${IFS}"
		IFS=","
		# shellcheck disable=SC2206
		sourceIPs=(${setIPs})
		IFS="${oldIFS}"

		local routing

		for value in "${sourceIPs[@]}"; do
			routing=$(jq -r ".routing.rules[0].source += [\"${value}\"]" ${configPath}09_routing.json)
			echo "${routing}" | jq . >${configPath}09_routing.json
		done

		reloadCore
		echoContent green "---> Add a landing machine to inbound and unblock Netflix successfully"
		exit 0
	be
	echoContent red "---> ip cannot be empty"
}

# Remove any door to unblock Netflix
removeDokodemoDoorUnblockNetflix() {

	unInstallOutbounds netflix-80
	unInstallOutbounds netflix-443
	unInstallRouting netflix-80
	unInstallRouting netflix-443
	rm -rf ${configPath}01_netflix_inbounds.json

	reloadCore
	echoContent green "---> Uninstall successfully"
}

# Restart the core
reloadCore() {
	if [[ "${coreInstallType}" == "1" ]]; then
		handleXray stop
		handleXray start
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		handleV2Ray stop
		handleV2Ray start
	be
}

# Check if vps supports Netflix
checkNetflix () {
	echoContent red "\nNotes"
	echoContent yellow "1. It can only detect whether vps supports Netflix"
	echoContent yellow "2. Unable to detect whether the proxy configuration supports Netflix after dns is unlocked"
	echoContent yellow "3. It can detect whether Netflix is ​​supported after vps configuration dns is unlocked\n"
	echoContent skyBlue "---> Checking"
	netflixResult=$(curl -s -m 2 https://www.netflix.com | grep "Not Available")
	if [[ -n ${netflixResult} ]]; then
		echoContent red "---> Netflix is ​​not available"
		exit 0
	be

	netflixResult=$(curl -s -m 2 https://www.netflix.com | grep "NSEZ-403")
	if [[ -n ${netflixResult} ]]; then
		echoContent red "---> Netflix is ​​not available"
		exit 0
	be

	echoContent skyBlue "---> Check if Breaking Bad can be played"
	result=$(curl -s -m 2 https://www.netflix.com/title/70143836 | grep "page-404")
	if [[ -n ${result} ]]; then
		echoContent green "---> Only self-made dramas are available"
		exit 0
	be
	echoContent green "---> Netflix Unlock"
	exit 0
}

# dns Unblock Netflix
dnsUnlockNetflix() {
	echoContent skyBlue "\nFunction 1/${totalProgress}: DNS unblock Netflix"
	echoContent red "\n=============================================================="
	echoContent yellow "1. Add"
	echoContent yellow "2. Uninstall"
	read -r -p "Please select:" selectType

	case ${selectType} in
	1)
		setUnlockDNS
		;;
	2)
		removeUnlockDNS
		;;
	esac
}

# Set dns
setUnlockDNS() {
	read -r -p "Please enter the DNS to unlock Netflix:" setDNS
	if [[ -n ${setDNS} ]]; then
		cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			{
				"address": "${setDNS}",
				"port": 53,
				"domains": [
					"geosite:netflix",
					"geosite:bahamut",
					"geosite:hulu",
					"geosite:hbo",
					"geosite:disney",
					"geosite:bbc",
					"geosite:4chan",
					"geosite:fox",
					"geosite:abema",
					"geosite:dmm",
					"geosite:niconico",
					"geosite:pixiv",
					"geosite:bilibili",
					"geosite:viu"
				]
			},
		"localhost"
		]
	}
}
EOF
		reloadCore

		echoContent green "\n ---> DNS unlock is added successfully, this setting is invalid for Trojan-Go"
		echoContent yellow "\n ---> If you still can't watch, you can try the following two solutions"
		echoContent yellow "1. Restart vps"
		echoContent yellow "2. After uninstalling dns and unlocking, modify the local [/etc/resolv.conf]DNS settings and restart vps\n"
	else
		echoContent red "---> dns cannot be empty"
	be
	exit 0
}

# Remove Netflix Unlock
removeUnlockDNS() {
	cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			"localhost"
		]
	}
}
EOF
	reloadCore

	echoContent green "---> Uninstall successfully"

	exit 0
}

# v2ray-core personalized installation
customV2RayInstall() {
	echoContent skyBlue "\n======================== Personalized installation================= =========="
	echoContent yellow "VLESS front, must install 0, if you only need to install 0, press Enter"
	if [[ "${selectCoreType}" == "2" ]]; then
		echoContent yellow "0.VLESS+TLS+TCP"
	else
		echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	be

	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.VMess+TLS+TCP"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	#	echoContent yellow "4.Trojan、Trojan+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	read -r -p "Please select [multiple choice], [example: 123]:" selectCustomInstallType
	echoContent skyBlue "--------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		selectCustomInstallType=0
	be
	if [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp xrayClean
		totalProgress = 17
		installTools 1
		# Apply for tls
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		# Random path
		if echo ${selectCustomInstallType} | grep -q 1 || echo ${selectCustomInstallType} | grep -q 3 || echo ${selectCustomInstallType} | grep -q 4; then
			randomPathFunction 5
			customCDNIP 6
		be
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# Install V2Ray
		installV2Ray 8
		installV2RayService 9
		initV2RayConfig custom 10
		cleanUp xrayDel
		installCronTLS 14
		handleV2Ray stop
		handleV2Ray start
		# Generate account
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red "---> Illegal input"
		customV2RayInstall
	be
}

# Xray-core personalized installation
customXrayInstall() {
	echoContent skyBlue "\n======================== Personalized installation================= =========="
	echoContent yellow "VLESS front, 0 is installed by default, if you only need to install 0, just select 0"
	echoContent yellow "0.VLESS+TLS/XTLS+TCP"
	echoContent yellow "1.VLESS+TLS+WS[CDN]"
	echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3.VMess+TLS+WS[CDN]"
	echoContent yellow "4.Trojan"
	echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
	read -r -p "Please select [multiple choice], [example: 123]:" selectCustomInstallType
	echoContent skyBlue "--------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		echoContent red "---> cannot be empty"
		customXrayInstall
	elif [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp v2rayClean
		totalProgress = 17
		installTools 1
		# Apply for tls
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		# Random path
		if echo "${selectCustomInstallType}" | grep -q 1 || echo "${selectCustomInstallType}" | grep -q 2 || echo "${selectCustomInstallType}" | grep -q 3 || echo "${selectCustomInstallType}" | grep -q 5; then
			randomPathFunction 5
			customCDNIP 6
		be
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# Install V2Ray
		installXray 8
		installXrayService 9
		initXrayConfig custom 10
		cleanUp v2rayDel

		installCronTLS 14
		handleXray stop
		handleXray start
		# Generate account
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red "---> Illegal input"
		customXrayInstall
	be
}

# Choose core installation---v2ray-core, xray-core
selectCoreInstall() {
	echoContent skyBlue "\nFunction 1/${totalProgress}: select core installation"
	echoContent red "\n=============================================================="
	echoContent yellow "1.Xray-core"
	echoContent yellow "2.v2ray-core"
	echoContent red "=============================================================="
	read -r -p "Please select:" selectCoreType
	case ${selectCoreType} in
	1)
		if [[ "${selectInstallType}" == "2" ]]; then
			customXrayInstall
		else
			xrayCoreInstall
		be
		;;
	2)
		v2rayCoreVersion=
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		be
		;;
	3)
		v2rayCoreVersion = v4.32.1
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		be
		;;
	*)
		echoContent red '---> selection error, select again'
		selectCoreInstall
		;;
	esac
}

# v2ray-core installation
v2rayCoreInstall() {
	cleanUp xrayClean
	selectCustomInstallType=
	totalProgress = 13
	installTools 2
	# Apply for tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	# initNginxConfig 5
	randomPathFunction 5
	# Install V2Ray
	installV2Ray 6
	installV2RayService 7
	customCDNIP 8
	initV2RayConfig all 9
	cleanUp xrayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleV2Ray stop
	sleep 2
	handleV2Ray start
	handleNginx start
	# Generate account
	checkGFWStatue 12
	showAccounts 13
}

# xray-core installation
xrayCoreInstall() {
	cleanUp v2rayClean
	selectCustomInstallType=
	totalProgress = 13
	installTools 2
	# Apply for tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	randomPathFunction 5
	# Install Xray
	handleV2Ray stop
	installXray 6
	installXrayService 7
	customCDNIP 8
	initXrayConfig all 9
	cleanUp v2rayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleXray stop
	sleep 2
	handleXray start

	handleNginx start
	# Generate account
	checkGFWStatue 12
	showAccounts 13
}

# Core management
coreVersionManageMenu() {

	if [[ -z "${coreInstallType}" ]]; then
		echoContent red "\n ---> The installation directory is not detected, please execute the script to install the content"
		menu
		exit 0
	be
	if [[ "${coreInstallType}" == "1" ]]; then
		xrayVersionManageMenu 1
	elif [[ "${coreInstallType}" == "2" ]]; then
		v2rayCoreVersion=
		v2rayVersionManageMenu 1

	elif [[ "${coreInstallType}" == "3" ]]; then
		v2rayCoreVersion = v4.32.1
		v2rayVersionManageMenu 1
	be
}
# Scheduled task check certificate
cronRenewTLS() {
	if [[ "${renewTLS}" == "RenewTLS" ]]; then
		renewalTLS
		exit 0
	be
}
# Account Management
manageAccount() {
	echoContent skyBlue "\nFunction1/${totalProgress}: Account Management"
	echoContent red "\n=============================================================="
	echoContent yellow "# Every time you delete or add an account, you need to review the subscription to generate a subscription\n"
	echoContent yellow "1. View account"
	echoContent yellow "2. View subscription"
	echoContent yellow "3. Add user"
	echoContent yellow "4. Delete user"
	echoContent red "=============================================================="
	read -r -p "Please enter:" manageAccountStatus
	if [[ "${manageAccountStatus}" == "1" ]]; then
		showAccounts 1
	elif [[ "${manageAccountStatus}" == "2" ]]; then
		subscribe 1
	elif [[ "${manageAccountStatus}" == "3" ]]; then
		addUser
	elif [[ "${manageAccountStatus}" == "4" ]]; then
		removeUser
	else
		echoContent red "---> wrong selection"
	be
}

# Subscribe
subscribe() {
	if [[ -n "${configPath}" ]]; then
		echoContent skyBlue "-------------------------Remarks--------------------- ------------"
		echoContent yellow "# Subscriptions will be regenerated when viewing subscriptions"
		echoContent yellow "# You need to check the subscription every time you add or delete an account"
		rm -rf /etc/v2ray-agent/subscribe/*
		rm -rf /etc/v2ray-agent/subscribe_tmp/*
		showAccounts >/dev/null
		mv /etc/v2ray-agent/subscribe_tmp/* /etc/v2ray-agent/subscribe/

		if [[ -n $(ls /etc/v2ray-agent/subscribe/) ]]; then
			find /etc/v2ray-agent/subscribe | while read -r email; do
				email=$(echo "${email}" | awk -F "[s][u][b][s][c][r][i][b][e][/]" '{print $2}')
				local base64Result
				base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/${email}")
				echo "${base64Result}" >"/etc/v2ray-agent/subscribe/${email}"
				echoContent skyBlue "--------------------------------------------------------------"
				echoContent yellow "email：$(echo "${email}" | awk -F "[_]" '{print $1}')\n"
				echoContent yellow "url：https://${currentHost}/s/${email}\n"
				echoContent yellow "Online QR code: https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentHost}/s/${email}\n"
				echo "https://${currentHost}/s/${email}" | qrencode -s 10 -m 1 -t UTF8
				echoContent skyBlue "--------------------------------------------------------------"
			done
		be
	else
		echoContent red "---> not installed"
	be
}

# main menu
menu() {
	cd "$HOME" || exit
	echoContent red "\n=============================================================="
	echoContent green "作者：mack-a"
	echoContent green "Current version: v2.5.32"
	echoContent green "Github：https://github.com/mack-a/v2ray-agent"
	echoContent green "Description: Eight-in-one coexistence script\c"
	showInstallStatus
	echoContent red "\n=============================================================="
	if [[ -n "${coreInstallType}" ]]; then
		echoContent yellow "1. Reinstall"
	else
		echoContent yellow "1. Install"
	be

	echoContent yellow "2. Any combination of installation"
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		echoContent yellow "3. Switch VLESS[XTLS]"
	elif echo ${currentInstallProtocolType} | grep -q 0; then
		echoContent yellow "3. Switch Trojan[XTLS]"
	be
	echoContent skyBlue "-------------------------tool management-------------------- ---------"
	echoContent yellow "4. Account Management"
	echoContent yellow "5. Replace the camouflage station"
	echoContent yellow "6. Update certificate"
	echoContent yellow "7. Replace CDN node"
	echoContent yellow "8.IPv6 offload"
	echoContent yellow "9.WARP diversion"
	echoContent yellow "10. Streaming media tools"
	echoContent yellow "11. Add a new port"
	echoContent yellow "12.BT download management"
	echoContent skyBlue "-------------------------version management-------------------- ---------"
	echoContent yellow "13.core management"
	echoContent yellow "14. Update script"
	echoContent yellow "15. Install BBR and DD scripts"
	echoContent skyBlue "-------------------------Script management-------------------- ---------"
	echoContent yellow "16. View log"
	echoContent yellow "17. Uninstall script"
	echoContent red "=============================================================="
	mkdirTools
	aliasInstall
	read -r -p "Please select:" selectInstallType
	case ${selectInstallType} in
	1)
		selectCoreInstall
		;;
	2)
		selectCoreInstall
		;;
	3)
		initXrayFrontingConfig 1
		;;
	4)
		manageAccount 1
		;;
	5)
		updateNginxBlog 1
		;;
	6)
		renewalTLS 1
		;;
	7)
		updateV2RayCDN 1
		;;
	8)
		ipv6Routing 1
		;;
	9)
		warpRouting 1
		;;
	10)
		streamingToolbox 1
		;;
	11)
		addCorePort 1
		;;
	12)
		btTools 1
		;;
	13)
		coreVersionManageMenu 1
		;;
	14)
		updateV2RayAgent 1
		;;
	15)
		bbrInstall
		;;
	16)
		checkLog 1
		;;
	17)
		unInstall 1
		;;
	esac
}
cronRenewTLS
menu