#!/bin/bash

# 结束统计结果
print_summary(){
    # 输出显示
    echo -e "\033[35m全部检测项: ${index} \033[0m"
    echo -e "\033[32m通过检测项: ${pass} \033[0m"
    echo -e "\033[31m失败检测项: ${fail} \033[0m"
    echo -e "\033[33m手工检测项: ${review} \033[0m"
}


index=0             # 记录所有检测项
pass=0              # 通过的检测项数
fail=0              # 未通过的检测项数
review=0            # 需手工复核的检测项数


# 系统检查项输出函数
OsPrint(){
    if [ "$5" = "True" ]; then ((pass++))
    elif [ "$5" = "False" ]; then ((fail++))
    else ((review++)); fi
    ((index++))

    echo "检查项名称: ${1}"
    echo "检查项说明: ${2}"
    echo "标准值: ${3}"
    echo "实际值: ${4}"
    echo "符合性: ${5}"
    echo "权重: ${6}"
    echo ""
}

check_1(){
    days=$(cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^\# | awk '{print $2}')    
    if [ -n "$days" ]; then  # 判断是否变量为空
        data4="PASS_MAX_DAYS=$days"
        if [ "$days" -le 90 ]; then  
            data5="True"
        else
            data5="False"
        fi
    else
        data4="在文件/etc/login.defs中未找到PASS_MAX_DAYS设置"
    fi
    data1='检查口令生存周期'
    data2='长期不修改密码会提高密码暴露风险，所以为了提高保密性，检查是否设置口令生存周期'
    data3='在文件/etc/login.defs中设置PASS_MAX_DAYS<=90'
    data6="重要"
    OsPrint $data1 $data2 $data3 $data4 $data5 $data6
}

check_2(){
    passminlen=$(cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^\# | awk '{print $2}')    
    if [ -n "$passminlen" ]; then
        data4="PASS_MIN_LEN=${passminlen}"
        if [ "$passminlen" -ge 8 ]; then
            data5="True" 
        else
            data5="False"
        fi
    else
        data4="在文件/etc/login.defs中未找到PASS_MIN_LEN设置"
    fi
    data1="检查口令最小长度"
    data2="长度小的口令存在被爆破出的风险，所以为了保证密码的安全，提高保密性需要检查口令最小长度"
    data3="在文件/etc/login.defs中设置PASS_MIN_LEN>=8"
    data6="重要"
    OsPrint $data1 $data2 $data3 $data4 $data5 $data6
}

check_3(){
    passwarn=$(cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^\# | awk '{print $2}')
    if [ -n "$passwarn" ]; then
        data4="PASS_WARN_AGE=${passwarn}"
        if [ "$passwarn" -ge 30 ]; then
            data5="True" 
        else
            data5="False"
        fi
    else
        data4="在文件/etc/login.defs中未找到PASS_WARN_AGE设置"
    fi
    data1="检查口令过期前警告天数"
    data2="为了防止口令过期而不知道，提高可用性。所以需要去检查设置口令过期警告天数。"
    data3="在文件/etc/login.defs中设置PASS_WARN_AGE>=30"
    data6="重要"
    OsPrint $data1 $data2 $data3 $data4 $data5 $data6
}

check_4_1(){
    # minlen:密码字符串长度，dcredit数字字符个数，ucredit大写字符个数，ocredit特殊字符个数，lcredit小写字符个数
    sign=0  # 标记符合的策略要求
    res=""
    # minlen=$(echo "$1" | awk -F 'minlen=' '{print $2}' | awk '{print $1}')
    dcredit=$(echo "$1" | awk -F 'dcredit=' '{print $2}' | awk -F '' '{print $2}')  # 获取第二个字符
    ucredit=$(echo "$1" | awk -F 'ucredit=' '{print $2}' | awk -F '' '{print $2}')
    ocredit=$(echo "$1" | awk -F 'ocredit=' '{print $2}' | awk -F '' '{print $2}')
    lcredit=$(echo "$1" | awk -F 'lcredit=' '{print $2}' | awk -F '' '{print $2}')
    if [ -n "$dcredit" ] && [ "$dcredit" -ge 1 ]; then ((sign++)); res="${res}dcredit=-${dcredit},"; fi
    if [ -n "$ucredit" ] && [ "$ucredit" -ge 1 ]; then ((sign++)); res="${res}ucredit=-${ucredit},"; fi
    if [ -n "$ocredit" ] && [ "$ocredit" -ge 1 ]; then ((sign++)); res="${res}ocredit=-${ocredit},"; fi
    if [ -n "$lcredit" ] && [ "$lcredit" -ge 1 ]; then ((sign++)); res="${res}lcredit=-${lcredit}"; fi
    data4=$res
    if [ "$sign" -ge 3 ]; then
        data5="True" 
    else
        data5="False"
    fi
}
check_4(){
    # CentOs系列
    if [ -e "/etc/pam.d/system-auth" ]; then
        raw=$(cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^\# )
        if [ -n "$raw" ]; then check_4_1 "$raw"; 
        else 
            data4="/etc/pam.d/system-auth文件中没有相关设置"
            data5="False"
        fi

    # Debian系列
    elif [ -e "/etc/pam.d/common-password" ]; then
        raw=$(cat /etc/pam.d/common-password | grep password | grep pam_cracklib.so | grep -v ^\# )
        if [ -n "$raw" ]; then check_4_1 "$raw";
        else 
            data4="/etc/pam.d/common-password文件中没有相关设置"
            data5="False"; 
        fi 
    else
        data4="/etc/pam.d/system-auth或/etc/pam.d/common-password配置文件不存在"
        data5="False"
    fi

    data1="检查设备密码复杂度策略"
    data2="口令过于简单会有被爆破出的风险，所以为了防止爆破风险，提高密码的保密性，需要检查设备的密码复杂度策略"
    data3="/etc/pam.d/system-auth或/etc/pam.d/common-password文件中存在 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 中任意3种，-1代表至少存在1个，可以比-1小。"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_5(){
    tmp=$(cat /etc/shadow | awk -F ":" '($2 == "" ) {print $1}' | xargs)
    if [ -z "$tmp" ]; then
        data4=$tmp
        data5="True" 
    else
        data4="存在空口令账号${tmp}"
        data5="False,"
    fi
    data1="检查是否存在空口令账号"
    data2="空口令会让攻击者可以不需要口令进入系统，危险性很大。所以需要检查是否存在空口令账号"
    data3="不存在空口令账号"
    data6="重要"
    OsPrint $data1 $data2 $data3 "$data4" $data5 $data6
}

check_6(){
    res=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | xargs)
    data4="现有UID为0的用户有${res}"
    if [ "root" = "$res"  ]; then
        data5="True" 
    else
        data5="False"
    fi
    data1="检查是否设置除root之外UID为0的用户"
    data2="不可设置除了root之外，第二个具有root权限的账号。为了提高可靠性，需要检查是否设置除了root之外UID为0的用户。"
    data3="没有除root之外UID为0的用户"
    data6="一般"
    OsPrint $data1 $data2 $data3 "$data4" $data5 $data6
}

check_7_1(){
    if [ -f "$1" ]; then
        res=$(cat $1 | grep -i umask | grep -v \# | awk '{print $2}' | xargs)
        data4="$1中umask为$res"
        res2=$(echo "$res" | awk '{print $1}')
        res3=$(echo "$res" | awk '{print $2}')
        if { [ -z "$res2" ] || [ "$res2" = "077" ]; } && { [ -z "$res3" ] || [ "$res3" = "077" ]; } ; then
            data5="True"
        else
            data5="False"
        fi
    else
        data4="$1文件不存在"
        data5="False"
    fi
    data1="检查文件$1中umask设置"
    data2="umask指文件权限的掩码。它是从权限中拿走相应的位（即bit）,且用户创建时不能赋予执行权限"
    data3="所有的umask值为077"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}
check_7(){
    check_7_1 "/etc/csh.cshrc" 
    check_7_1 "/etc/bashrc" 
    check_7_1 "/etc/profile"
}

check_8_1(){
    if [ -f "$1" ]; then
        stat=$(stat -c %a "$1")  
        data4="$stat"
        if [ "$stat" -eq "$2" ]; then
            data5="True"
        else
            data5="False"
        fi
        data1="检查$1文件权限是否符合规范"
        data3="$2"
    elif [ -d "$1" ]; then
        stat=$(stat -c %a "$1")  
        data4="$stat"
        if [ "$stat" -eq "$2" ]; then
            data5="True"
        else
            data5="False"
        fi
        data1="检查$1目录权限是否符合规范"
        data3="$2"
    else
        data1="检查$1文件权限是否符合规范"
        data3="$2"
        data4="$1文件不存在"
        data5="review"
    fi
    data2="为了提高安全可靠性需要检查重要目录或文件的权限设置"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}
check_8(){
    # 文件
    check_8_1 "/etc/xinetd.conf" 600
    check_8_1 "/etc/group" 644
    check_8_1 "/etc/shadow" 400
    check_8_1 "/etc/services" 644
    check_8_1 "/etc/passwd" 644
    check_8_1 "/etc/grub.conf" 600
    check_8_1 "/boot/grub/grub.conf" 600
    check_8_1 "/etc/lilo.conf" 600
    # 目录
    check_8_1 "/tmp" 750
    check_8_1 "/etc/security" 600
    check_8_1 "/etc/rc0.d" 750
    check_8_1 "/etc/rc1.d" 750
    check_8_1 "/etc/rc2.d" 750
    check_8_1 "/etc/rc3.d" 750
    check_8_1 "/etc/rc4.d" 750
    check_8_1 "/etc/rc5.d" 750
    check_8_1 "/etc/rc6.d" 750
    check_8_1 "/etc/rc.d/init.d" 750
}

check_9_1(){
    if [ -f "$1" ]; then
        lsattr=$(lsattr "$1" | awk '{ print $1 }' | awk -F "-" '{print $5}')
        lsattr2=$(lsattr "$1" | awk '{print $1}')
        data4="$lsattr2"
        if [ "$lsattr" = "i" ]; then
            data5="True"
        else
            data5="False"
        fi
    else
        data4="$1文件不存在"
        data5="review"        
    fi
    data1="检查$1文件属性"
    data2="为了提高完整性、可用性、可靠性，需要检查重要文件的属性设置;应对重要文件设置i属性，使其不能对文件进行删除、改名、添加、修改等操作"
    data3="----i--------e--"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}
check_9(){
    check_9_1 "/etc/passwd"
    check_9_1 "/etc/shadow"
    check_9_1 "/etc/group"
    check_9_1 "/etc/gshadow"
}

check_10(){
    tt=$(cat /etc/login.defs | grep -i UMASK | grep -v \# | awk '{print $2}')
    data4="$tt"
    if [ "$tt" = "027" ]; then
        data5="True" 
    else
        data5="False"
    fi
    data1="检查用户目录缺省访问权限设置"
    data2="为了满足信息安全要求的保密性，需要检查用户目录缺省访问权限设置;如设置缺省权限为027 ，则用户默认的目录访问权限为750"
    data3="027"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_11(){
    banner=$(cat /etc/ssh/sshd_config | grep -i Banner | grep -v \# | awk '{print $2}')
    if [ -n "$banner" ]; then
        data4="当前Banner文件为$banner,请自行核查设置是否合理"
        data5="review" 
    else
        data4="未设置警告Banner。"
        data5="False"
    fi
    data1="检查是否设置SSH登录前警告Banner"
    data2="为了保证信息安全抗抵赖性，可靠性。需检查是否设置ssh登录前的警告Banner信息，警示登录系统的人员。"
    data3="已设置ssh登录前的Banner信息"
    data6="可选"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_12_1(){
    if [ -f "$1" ]; then
        other=$(stat -c %a /var/log/cron | awk -F "" '{print $3}')
        data4="实际其他用户权限为$other"
        if [ "$other" -le 5 ]; then
            data5="True"
        else
            data5="False"
        fi
    else
        data4="$1文件不存在"
        data5="review"
    fi
    data1="检查$1日志文件是否其他用户不可写"
    data2="为了保证信息安全的可审计性和完整性，需要检查日志文件是否非全局可写。"
    data3="非同组的其他用户不可写，即其他用户权限<=5"
    data6="可选"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}
check_12(){
    check_12_1 "/var/log/cron"
    check_12_1 "/var/log/secure"
    check_12_1 "/var/log/boot.log"
    check_12_1 "/var/log/messages"
    check_12_1 "/var/log/mail"
    check_12_1 "/var/log/localmessages"
    check_12_1 "/var/log/spooler"
    check_12_1 "/var/log/maillog"
}

check_13(){
    su=$(cat /etc/rsyslog.conf | grep ^authpriv | awk '{print $1,$2}')
    if [ -n "$su" ]; then
        data4="$su"
        data5="True"
    else
        data="没有找到配置项"
        data5="False"
    fi
    data1="检查是否配置su命令使用情况记录"
    data2="Linux su（英文全拼：swith user）命令用于变更为其他使用者的身份，除root外，需要键入该使用者的密码。为了保证信息安全的可审计性、抗抵赖性，需要检查是否配置su命令使用情况记录"
    data3="已配置su命令使用情况的记录文件：authpriv.* /var/log/secure"
    data6="可选"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_14(){
    res=$(cat /etc/ssh/sshd_config | grep -i Protocol | grep -v \#)
    res2=$(cat /etc/ssh/sshd_config | grep -i Protocol | grep -v \# | awk '{print $2}')
    data4="$res"
    if [ -n "$res2" ] && [ "$res2" = "2" ]; then
        data5="True"
    else
        data5="False"
    fi
    data1="检查系统openssh安全配置"
    data2="Openssh是使用加密的远程登录实现，可以有效保护登录及数据的安全，为了保证信息安全的保密性、可靠性，需要检查系统openssh安全配置。注意该配置需要有多个账号，而不是只有一个root账号。"
    data3="在sshd_config中配置：Protocol 2"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_15(){
    res=$(find / -name snmpd.conf)
    res2=$(ps -ef | grep "snmp" | grep -v "grep")
    if [ -n "$res" ] || [ -n "$res2" ]; then
        data4="已安装snmp服务，请手工确认snmpd.conf文件中的默认团体字已修改为用户自定义团体字"
        data5="review"
    else
        data4="未安装snmp服务。"
        data5="True"
    fi
    data1="检查是否已修改snmp的默认团体字"
    data2="为了保证信息安全的保密性，需要检查是否已修改snmp默认团体字;因为snmp的默认团体字存在安全漏洞，导致服务器信息泄露"
    data3="系统未安装snmp服务或已修改默认团体字"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_16(){
    tmp=$(ps -ef | grep -v grep | grep -w ftp)
    if [ -z "$tmp" ]; then
        data4="未启用ftp服务"
        data5="True"
    else
        root=$(cat /etc/vsftpd/ftpusers | grep "root" | grep -v ^\#)
        if [ -n "$root" ]; then
            data4="FTP服务已启用,已禁止root用户登录ftp"
            data5="True"
        else
            data4="FTP服务已启用,未禁止root用户登录ftp"
            data5="False"
        fi
    fi
    data1="检查是否已禁止root用户登录ftp"
    data2="因为root用户权限过大，容易导致系统文件误删除。"
    data3="系统未安装ftp服务或已禁止root用户登录"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_17(){
    tmp=$(ps -ef | grep -v grep | grep -w ftp)
    if [ -z "$tmp" ]; then
        data4="未启用ftp服务"
        data5="True"
    else
        tmp2=$(cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable=NO" | grep -v ^\#)
        if [ -n "$tmp2" ]; then
            data4="已禁止匿名用户登录FTP"
            data5="True"
        else
            data4="未禁止匿名用户登录FTP"
            data5="False"
        fi
    fi
    data1="检查是否禁止匿名用户登录FTP"
    data2="匿名用户多被黑客用来进入ftp.在/etc/passwd文件中，删除ftp用户;编辑/etc/vsftpd.conf(或/etc/vsftpd/vsftpd.conf)文件，设置：anonymous_enable=NO"
    data3="系统未安装ftp服务或已禁止匿名用户登录"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_18(){
    tmp=$(cat /etc/profile | grep "export TMOUT=" | awk -F "=" '{print $2}')
    if [ -n "$tmp" ]; then
        if [ "$tmp" -le 600 ]; then
            data4="$tmp"
            data5="True"
        else
            data4="$tmp"
            data5="False"
        fi
    else
        data4="未设置命令行界面超时退出时间"
        data5="False"
    fi
    data1="检查是否设置命令行界面超时退出时间"
    data2="以root账户执行，vi /etc/profile末尾增加 export TMOUT=600(单位：秒，可根据具体情况设定超时退出时间，要求不大于600秒),注销用户，再用该用户登录激活该功能"
    data3="不大于600秒"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_19(){
    tmp=$(cat /etc/security/limits.conf | grep -i "\* hard core 0")
    tmp2=$(cat /etc/security/limits.conf | grep -i "\* soft core 0")
    if [ -n "$tmp" ] && [ -n "$tmp2" ]; then
        print_info "已配置系统core dump"
        data5="True"
    else
        data4="未配置系统core dump"
        data5="False"
    fi
    data1="检查系统core dump设置"
    data2="当程序运行的过程中异常终止或崩溃，操作系统会将程序当时的内存状态记录下来，保存在一个文件中，这种行为就叫做Core Dump（中文有的翻译成: 核心转储)。"
    data3="在文件/etc/security/limits.conf中配置* hard core 0 和 * soft core 0"
    data6="一般"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}

check_20(){
    tmp=$(df -h | grep ^/dev | awk '{print $5}' | sed 's/%//')
    data4="$tmp%"
    if [ "$tmp" -le 80 ]; then
        data5="True"
    else
        data5="False"
    fi
    data1="检查系统磁盘根分区使用率"
    data2="系统磁盘根分区使用率过高，会导致系统运行缓慢，甚至进入假死状态"
    data3="<=80%"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}



# 检查Nginx是否已安装启用
checkNginxInstall(){
    command=$(ps -ef | grep nginx | grep -v "grep")
    if [ -n "$command" ]; then
        echo "Nginx已安装并启用"

        config_file=$(find / -name "nginx.conf" | xargs | awk '{print $1}')
        checkNginxVersion
        checkVisitLog
        checkErrorLog
    else
        echo "本机没有安装或启用Nginx"
    fi
}
checkNginxVersion(){
    file=$(find / -name "nginx" -type f | xargs | awk '{print $1}')
    if [ -x "$file" ]; then
        echo "Nginx基本信息如下:"
        $file -V
    else
        echo "$file 文件不可执行。"
    fi
    echo ""
}
checkVisitLog(){	
    if [ -n "$config_file" ]; then
        data2="Nginx的配置文件为: $config_file"

	    check_access_log='^\s*access_log\s*logs/access.log\s*main;'
        res=$(cat "$config_file" | grep -E "$check_access_log")
        if [ -z "$res" ]; then
            data4="Nginx的访问日志未开启"
            data5="False"
        else
            data4="Nginx访问日志已开启：$res"
            data5="True"
        fi
    else
        data2="没有找到nginx的配置文件"
        data4=""
        data5="review"
    fi
    data1="检查Nginx的访问日志是否开启"
    data3="开启access_log"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}
checkErrorLog(){
    if [ -n "$config_file" ]; then
        data2="Nginx的配置文件为: $config_file"

        check_error_log='^\s*log_format\s*main'
        res=$(cat "$config_file" | grep -E "$check_error_log")

        if [ -z "$res" ]; then
            data4="Nginx的错误日志未开启"
            data5="False"
        else
            data4="Nginx错误日志已开启：$res"
            data5="True"
        fi
    else
        data2="没有找到nginx的配置文件"
        data4=""
        data5="review"
    fi

    data1="检查Nginx的错误日志是否开启"
    data3="开启error_log"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}
checkAutoindex(){
    if [ -n "$config_file" ]; then
        data2="Nginx的配置文件为: $config_file"

        result=$(cat "$config_file" | grep -i "autoindex" | grep -v "\#" | awk '{print $2}')
        if [ -z "$result" ] || [ "$result" = "off" ]; then
            data4="已关闭目录列表功能"
            data5="True"
        elif [ "$result" = "on" ]; then
            data4="已开启目录列表功能，autoindex参数的值为$result"
            data5="False"
        else
            data4="autoindex参数的值为$result,请人工审核"
            data5="review"
        fi
    else
        data2="没有找到nginx的配置文件"
        data4=""
        data5="review"
    fi

    data1="检查是否关闭Nginx的目录列表功能"
    data3="在nginx.conf中，autoindex参数的值为off,或者没有该参数"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}



# 检查Apache是否已安装启用
checkApacheInstall(){
    command=$(ps -ef | grep "httpd" | grep -v "grep")
    if [ -n "$command" ]; then
        echo "Apache已安装并启用"
        apache_file=$(find / -name "httpd" -type f | xargs | awk '{print $1}')
        apache_conf=$($apache_file -V | grep -E "HTTPD_ROOT|SERVER_CONFIG_FILE" | awk -F "=" '{print $2}' | xargs | sed 's/\s/\//')

        checkApacheVersion
        checkhtaccess
        checkFilelist
    else
        echo "本机没有安装或启用Apache"
    fi
}
checkApacheVersion(){
    if [ -x "$apache_file" ]; then
        echo "Apache基本信息如下:"
        $apache_file -v
    else
        echo "$apache_file 文件不可执行。"
    fi
    echo ""
}
checkhtaccess(){
	include=$(cat "$apache_conf" | grep -B10 "AllowOverride" | grep -A10 "<Directory />" | awk '{if($0~/AllowOverride/)print$2}')

    for i in $include; do
        if echo "$i" | grep -qwi "none"; then
            data4="未启用.htaccess配置"
            data5="True"
        else
            data4="已启用.htaccess配置"
            data5="False"
            break
        fi
    done

    data1="检查Apache是否关闭.htaccess配置"
    data2=".htaccess是一个纯文本文件，主要针对当前目录,它里面存放着Apache服务器配置相关的指令;它主要的作用有：URL重写、自定义错误页面、MIME类型配置以及访问权限控制等。"
    data3="关闭.htaccess配置"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"

}
checkFilelist(){
	include1=$(cat $apache_conf | awk '{if($0~/Options Indexes/)print$0}' | grep -v "\#")
	if [ -n "$include1" ]; then
        data4="已启用Apache的目录列表功能"
        data5="False"
	else
        data4="未开启Apache的目录列表功能"
        data5="True"
	fi

    data1="检查Apache的目录列表功能是否关闭"
    data2="Apache的配置文件为 $apache_conf"
    data3="关闭Apache的目录列表功能"
    data6="重要"
    OsPrint "$data1" "$data2" "$data3" "$data4" "$data5" "$data6"
}




checktomcat1(){
        echo "tomcat版本信息:"
        version=$(/opt/apache-tomcat-8.0.53/bin/version.sh | grep version)
        echo "$version"

}

checktomcat2(){
        # print_check_point '自动部署开关是否打开'
        include2=$(cat /opt/apache-tomcat-8.0.53/conf/server.xml | awk '{if($0~"autoDeploy")print}'| awk '{print $2}'|awk -F "[\"]" '{print $2}')      
        if [ $include2 == true ];then
           echo "自动部署打开，建议关闭，容易被部署恶意或未经测试的应用程序"
        else
           echo "自动部署关闭"
        fi
}

checktomcat3(){
        # print_check_point '禁止Tomcat显示目录文件列表'
        include3=$(cat /opt/apache-tomcat-8.0.53/conf/web.xml | awk '{if($1~"<param-value>false</param-value>")print}'|awk 'NR==1{print}'| awk -F '>' '{print $2}'|awk -F '<' '{print $1}')
        if [ $include3 == false ];then
           echo "系统禁止Tomcat显示目录文件列表"
        else
           echo "警告！tomcat可以显示目录文件列表"
        fi
}






Check_MysqlVersion(){
    echo "----------------------------Mysql版本检查----------------------------------"
    count=$(find / -name mysql | grep /bin/mysql -c)
    echo "当前系统安装了$count个版本的mysql服务"
    for i in $(find / -name mysql | grep /bin/mysql); do 
        version=$($i -V | awk '{print $5}' | awk -F , '{print $1}')
        echo "已安装Mysql版本：$version，安装路径：$i"
    done   
}

checkList(){
    echo "----------------------------mysql配置检查----------------------------------"
    Configuration=$(find / -name my.cnf | grep /etc/my.cnf)
    for i in $Configuration; do 
        a=$(cat $i | grep '^local-infile')
        if [ "$a" != "local-infile = false" ]; then
            echo "---------------------1.禁用mysql对本地文件存取的功能---------------------------"
            echo "修改配置文件$i,在文件中的[mysqld]区域插入如下内容:"
            echo "local-infile = false"
        fi
    done  
    Configuration=$(find / -name my.cnf | grep /etc/my.cnf)
    for i in $Configuration; do 
        a=$(cat $i | grep '^#log-bin' | head -n 1)
        if [ "$a" = "#log-bin=mysql-bin" ]; then
            echo "-------------------------2.检查是否配置日志功能-----------------------------"
            echo "修改配置文件$i,在文件中的[mysqld]区域插入如下内容:"
            echo "1.log-bin=/***/*** #开启二进制日志,将替换为实际日志存储路径;2.log-error=/***/*** #开启错误日志,将替换为实际日志存储路径"
        fi
    done  
    Configuration=$(ps -ef|grep "mysqld"|grep -v "grep"|awk '{print $1}')
    f=$(find / -name my.cnf | grep /etc/my.cnf)
    for i in $Configuration; do 
        if [ "$i" = "root" ]; then
            echo "--------------------3.检查是否禁止mysql以管理员账号权限运行----------------------"
            echo "修改配置文件$f,在文件中的[mysqld]区域插入如下内容:"
            echo "user=mysql"
        fi
    done  
}






Check_PHPVersion(){
    echo "----------------------------PHP版本检查----------------------------------"
    version=$(php -v | awk '{print $2}'| awk 'NR==1')
    a=$(echo $version | awk -F . '{print $1}')
    echo "PHP版本为：$version"
    if [ "$a" -lt "8" ]; then
        echo "当前PHP不是最新版本，建议更新"
    fi
}

checkList2(){
    echo "----------------------------PHP配置检查----------------------------------"
    Configuration=$(find / -name php.ini | grep /etc/php.ini)
	a=$(cat $Configuration | grep '^safe_mode' | head -n 1)
    b=$(cat $Configuration | grep '^safe_mode_gid')
    c=$(cat $Configuration | grep '^register_globals')
    d=$(cat $Configuration | grep '^allow_url_fopen')
    e=$(cat $Configuration | grep '^allow_url_include')
    f=$(cat $Configuration | grep '^magic_quotes_gpc')
    g=$(cat $Configuration | grep 'open_basedir ')
    h=$(cat $Configuration | grep '^disable_functions=')
    if [ "$a" != "safe_mode=On" ]; then
        echo "-------------------------1.启用PHP安全模式-------------------------------"
        echo "建议启用PHP安全模式：safe_mode=On"
        echo "启用safe_mode，会对许多PHP函数进行限制，特别是和系统相关的文件打开、命令执行等函数。所有操作文件的函数将只能操作与脚本UID相同的文件。能在很大程度上提高PHP应用的安全性。"
    fi
    if [ "$a" = "safe_mode=On" -a "$b" != "safe_mode_gid=Off" ]; then
        echo "--------------------------2.用户组安全--------------------------------"
        echo "建议设置:safe_mode_gid=Off"
        echo "当safe_mode打开时，safe_mode_gid没关闭，那么php脚本能够对文件进行访问，而且相同组的用户也能够对文件进行访问。"
        echo "如果不进行设置，可能我们无法对我们服务器网站目录下的文件进行操作了，比如我们需要对文件进行操作的时候。"
    fi
    if [ "$c" != "register_globals=Off" ]; then
        echo "-------------------------3. 关闭注册全局变量-------------------------------"
        echo "建议关闭注册全局变量：register_globals=Off"
        echo "攻击者能通过提交数据来给PHP应用中的未初始化变量赋值，改变代码逻辑，产生安全问题。"
    fi
    if [ "$d" != "allow_url_fopen=Off" ]; then
        echo "-------------------------4. 本地文件包含-------------------------------"
        echo "文件操作存在风险，建议配置项：allow_url_fopen=Off"
        echo "PHP的远程文件包含和远程文件操作功能在通常的应用中都不会用到,如果PHP代码在文件操作或是文件包含的时候对其变量不作严格的检查,攻击者就可以通过改变这些变量的值来包含远程机器上的恶意文件,并在WEB服务器上运行任意代码。"
    fi
    if [ "$e" != "allow_url_include=Off" ]; then
        echo "-------------------------5. 远程文件包含-------------------------------"
        echo "文件操作存在风险，建议配置项：allow_url_include=Off"
        echo "PHP的远程文件包含和远程文件操作功能在通常的应用中都不会用到,如果PHP代码在文件操作或是文件包含的时候对其变量不作严格的检查,攻击者就可以通过改变这些变量的值来包含远程机器上的恶意文件,并在WEB服务器上运行任意代码。"
    fi
    if [ "$f" != "magic_quotes_gpc=On" ]; then
        echo "-------------------------6. 打开引号转义-------------------------------"
        echo "建议配置项：magic_quotes_gpc=On"
        echo "如果PHP代码中没有对用户输入数据中的特殊字符作过滤就直接用于构造SQL查询串,将产生SQL注入漏洞。"
        echo "该选项使得从GET, POST, COOKIE来的变量自动加了addslashes()操作,对输入字符串中的单引号,双引号,括号会进行转义操作,虽不能通过打开这个选项来完全解决 SQL注入问题,但能在一定程度上加大注入的难度。"
    fi
    if [ "$g" = ";open_basedir =" ]; then
        echo "--------------------------7. 禁止跨目录--------------------------------"
        echo "建议配置项：open_basedir =/var/www/"
        echo "限制PHP代码中文件操作函数能操作的目录，防止代码中的错误或是受到攻击时能破坏的文件范围。建议根据具体使用要求，进一步细化配置值。"
    fi
    if [ "$h" = "disable_functions=" ]; then
        echo "--------------------------8. 禁止危险函数--------------------------------"
        echo "建议配置项：disable_functions=assert,phpinfo,eval,passthru,exec,system,chroot,scandir,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_alter,ini_restore,dl,pfsockopen,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,fsocket,fsockopen"
        echo "按需要禁止部分函数和类"
    fi
}






Check_DockerVersion(){
    echo "----------------------------docker版本检查----------------------------------"
    docker version
}
Security_Audit(){
    echo "-------------------------------安全审计-------------------------------------"
    echo "除了审核常规的Linux文件系统和系统调用之外，还审核所有与Docker相关的文件和目录。Docker守护程序以“ root”特权运行。其行为取决于某些关键文件和目录"
    echo "加固建议：在/etc/audit/audit.rules与/etc/audit/rules.d/audit.rules文件中添加以下行："
    echo "-w /var/lib/docker -k docker"
    echo "-w /etc/docker -k docker"
    echo "-w /usr/lib/systemd/system/docker.service -k docker"
    echo "-w /usr/lib/systemd/system/docker.socket -k docker"
    echo "-w /usr/bin/docker-containerd -k docker"
    echo "-w /usr/bin/docker-runc -k docker"
}

checkList3(){
    echo "-----------------------------检查服务配置------------------------------------"
    a=$(cat /usr/lib/systemd/system/docker.service | grep '^ExecStart')
    b=$(cat /usr/lib/systemd/system/docker.service | grep '^ExecStart' | grep '\-\-icc=false')
    c=$(cat /usr/lib/systemd/system/docker.service | grep '^ExecStart' | grep '\-\-log\-level="info"')
    if [ "$a" != "$b" ]; then
        echo "------------------------1.限制容器之间的网络流量------------------------------"
        echo "加固建议:文件中的ExecStart参数添加 --icc=false选项 "
        echo "然后重启docker服务:1.systemctl daemon-reload 2.systemctl restart docker"
    fi
    if [ "$a" != "$c" ]; then
        echo "------------------------2.设置日志记录级别------------------------------"
        echo "加固建议:文件中的ExecStart参数添加 --log-level="info"项 "
        echo "然后重启docker服务:1.systemctl stop docker 2.systemctl start docker"
    fi
    
}





echo "------------------------ 检查Linux系统脆弱项配置 ------------------------"
check_1   # 检查是否设置密码生存周期
check_2   # 检查是否设置密码最小长度
check_3   # 检查是否设置密码过期前的警告天数
check_4   # 检查设备密码复杂度策略
check_5   # 检查是否存在空口令账号
check_6   # 检查是否设置除root之外UID为0的用户
check_7   # 检查用户umask设置
check_8   # 检查重要目录或文件权限设置
check_9   # 检查重要文件属性设置--需重启
check_10  # 检查用户目录缺省访问权限设置
check_11  # 检查是否设置SSH登录前警告的Banner
check_12  # 检查日志文件是否非全局可写
check_13  # 检查是否配置su命令使用情况记录
check_14  # 检查系统openssh安全配置
check_15  # 检查是否已修改snmp默认团体字
check_16  # 检查是否禁止root用户登录ftp
check_17  # 检查是否禁止匿名用户登录ftp
check_18  # 检查是否设置命令行界面超时退出时间
check_19  # 检查系统core dump设置
check_20  # 检查系统磁盘根分区使用率

# 检查Nginx脆弱项配置
echo "------------------------ 检查Nginx脆弱项配置 ------------------------"
checkNginxInstall
echo ""

# 检查Apache脆弱项配置
echo "------------------------ 检查Apache脆弱项配置 ------------------------"
checkApacheInstall
echo ""

echo "------------------------ 检查Tomcat的脆弱项配置 ------------------------"
checktomcat1
checktomcat2
checktomcat3
echo ""
echo ""

echo "------------------------ 检查MySql的脆弱项配置 ------------------------"
Check_MysqlVersion
checkList
echo ""
echo ""


echo "------------------------ 检查PHP的脆弱项配置 ------------------------"
Check_PHPVersion
checkList2
echo ""
echo ""


echo "----------------------------检查Docker的脆弱项配置----------------------------------"
Check_DockerVersion
Security_Audit
checkList3
echo ""
echo ""
