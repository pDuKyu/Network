import streamlit as st
import pandas as pd
from datetime import datetime
import random















#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# 기본설정
basic_data = {
    "명령어": ["enable", "configure terminal", "hostname *", "enable secret ~", "line con 0", "service password-encryption", "banner motd #HI#", "no ip domain-lookup", "service timestamps log datatime msec", "show version"],
    "설명": ["관리자 모드 (enable 모드)로 전환", "글로벌 설정(config) 모드로 전환", "장비 이름을 '*'로 변경 (장소나 특징을 구별할 수 있는 이름)", "관리자 모드 비밀번호를 '~'로 설정 (입력 후 암호화 됨)", "콘솔 접속 가능 설정", "설정된 모든 패스워드 암호화", "접속 시 #HI#라는 배너 띄우기 (경고 문구 등에 사용)", "DNS 찾지 말고 명령어 종료", "입력된 로그에 시간을 함께 추가", "장비 세부 정보 확인 (uptime, image file(경로: 파일명),  model number, system serial number 등)"]
}

# 원격 접근 보안 설정
remote_access_data = {
    "명령어": ["line vty 0 15", "password 7291", "login", "logging synchronous", "exec-timeout 1 0"],
    "설명": ["동시에 16개의 원격 접속 가능 설정 (버츄얼 텔 타입)", "암호를 '7291'로 설정", "로그인 할 때 암호 요청 설정", "입력 중 로그가 들어와도 입력 값을 이어가게 설정", "1분간 입력 안 하면 접속 종료"]
}

# VLAN 설정 명령어 데이터
vlan_data = {
    "명령어": ["show vlan", "vlan 2", "name computers", "interface ~", "switchport mode access", "switchport access vlan 2", "", "show interfaces '포트번호' switchport"],
    "설명": ["현재 VLAN 설정을 표시", "VLAN 번호가 2인 VLAN을 생성", "VLAN의 이름을 'computers'로 설정", "~ 인터페이스에 접근", "해당 스위치포트를 Access 모드로 설정", "해당 스위치포트 Access를 VLAN 2로 지정", "", "지정된 포트의 스위치포트 설정 정보를 표시"]
}

# VTP 명령어
vtp_commands = {
    "명령어": ["vtp mode {server/client/transparent}", "vtp domain domain-name", "vtp password password", "vtp pruning", "vtp version {1/2/3}", "vtp file {filename}", "", "show vtp status", "show vtp counters", "clear vtp counters", "clear vtp counters {interface}"],
    "설명": ["VTP 모드 설정", "VTP 도메인 이름 설정", "VTP 도메인 옵션 비밀번호 설정(server의 설정을 client가 적용시에도 사용)", "VTP Pruning 활성화", "VTP 버전 설정", "VTP 설정 파일 저장 또는 불러오기", "", "현재 VTP 설정 상태 표시", "VTP 정보 교환에 대한 통계 표시", "VTP 통계 재설정", "특정 인터페이스의 VTP 통계 재설정"]
}

# 트렁크 프로토콜 명령어
trunk_protocol_data = {
    "명령어": ["interface <인터페이스 이름>", "switchport mode trunk", "switchport trunk allowed vlan <VLAN 번호>", "switchport mode trunk vlan add <VLAN 번호>", "switchport trunk native vlan <VLAN 번호>"],
    "설명": ["설정하려는 인터페이스로 이동", "해당 인터페이스를 트렁크 모드로 설정", "트렁크에서 허용할 VLAN을 지정", "트렁크에 VLAN 추가", "해당 인터페이스의 네이티브 VLAN을 설정"]
}

# 부트 이미지 변경 명령어
boot_image_change = {
    "명령어": ["dir", "copy tftp: flash", "dir", "conf t", "boot system flash:파일명", "", "show boot"],
    "설명": ["파일 경로 확인", "TFTP 서버에서 이미지 파일을 복사하여 라우터의 플래시 메모리에 저장", "파일 재확인", "설정 터미널 열기", "라우터가 부팅할 때 사용할 이미지를 지정", "", "부팅 이미지 지정 확인"]
}

# 로그 저장 서버 명령어
server_logs = {
    "명령어": ["configure terminal", "logging host 000.000.000.000", "logging trap debugging"],
    "설명": ["관리자 모드 진입", "로그를 저장할 서버의 IP 설정", "디버깅 로그 저장 설정"]
}

# 원격 접속을 위한 스위치 IP 할당 명령어
remote_access_switch = {
    "명령어": ["conf t", "interface vlan 1", "ip address [IP 주소] [서브넷 마스크]", "no shutdown", "end", "ip default-gateway x.x.x.x", "", "show ip interface brief"],
    "설명": ["구성 모드 진입", "VLAN 1 인터페이스 선택", "IP 주소와 서브넷 마스크 할당", "인터페이스 활성화", "설정 모드 종료", "게이트웨이 설정", "", "인터페이스 상태 확인"]
}

# 트래킹 설정 명령어
tracking_commands = {
    "명령어": ["track 10 interface e1/1 line-protocol", "interface vlan 10", "standby track 10 decrement 100"],
    "설명": [ "트랙 10번은 e1/1의 연결 상태를 주시", "vlan 10 접근", "트랙 10번이 문제를 감지할 시 vlan10의 priority값을 100 뺌 (문제가 해결되면 다시 값을 돌려 놓음)"]
}

# 트렁크 설정 명령어
trunk_protocol_commands = {
    "명령어": ["interface <인터페이스 이름>", "switchport mode trunk", "switchport trunk allowed vlan <VLAN 번호>", "switchport mode trunk vlan add <VLAN 번호>"],
    "설명": ["설정하려는 인터페이스로 이동", "해당 인터페이스를 트렁크 모드로 설정", "트렁크에서 허용할 VLAN을 지정", "트렁크에 VLAN 추가"]
}

# 네이티브 vlan 설정 명령어
native_vlan_commands = {
    "명령어": ["interface <인터페이스 이름>", "switchport trunk native vlan <VLAN 번호>"],
    "설명": ["설정하려는 인터페이스로 이동", "해당 인터페이스의 네이티브 VLAN을 설정"]
}

# STP 설정 명령어
stp_settings = {
    "명령어": ["show spanning-tree vlan [x]", "spanning-tree mode [...]", "spanning-tree vlan [x] priority [....]", "spanning-tree vlan [x] root primary", "spanning-tree vlan [x] root secondary", "spanning-tree vlan [x] cost [...]"],
    "설명": ["특정 VLAN의 스패닝 트리 설정 확인", "스패닝 트리 프로토콜 모드 변경", "특정 VLAN의 루트 브리지 우선순위 설정", "특정 VLAN에서 스위치가 루트 브리지로 자동 선출", "특정 VLAN에서 스위치가 루트 브리지 후보로 자동 선출", "특정 VLAN의 인터페이스 STP 경로 비용 변경"]
}

# 루트 브릿지 보안 설정 명령어
root_bridge_security = {
    "코드": ["spanning-tree portfast", "spanning-tree guard root", "spanning-tree bpduguard enable", "spanning-tree bpdufilter enable", "spanning-tree loopguard default", "spanning-tree vlan ~ root primery", "spanning-tree vlan ~ root seconfdery"],
    "설명": ["리스닝/러닝 단계를 건너뛰는 포트를 설정", "해당 인터페이스가 Root Port가 되지 않게 설정", "해당 인터페이스에 BPDU가 들어오면 차단", "BPDU를 해당 포트로 송/수신하지 않음", "어떤 이벤트가 일어나도 이 포트를 BLK로 유지(BLK포트에만 적용 가능)", "vlan을 루트 브릿지로 설정", "vlan을 두번 째 브릿지로 설정"]
}

# 트래킹 설정 명령어
tracking_data = {
    "명령어": ["track 10 interface e1/1 line-protocol", "interface vlan 10", "standby track 10 decrement 100"], 
    "설명": ["트랙 10은 인터페이스 e1/1의 라인 프로토콜 연결 상태를 모니터링합니다.", "VLAN 10에 대한 인터페이스 설정을 수행합니다.", "트랙 10이 문제를 감지하면 VLAN 10의 우선 순위 값을 100만큼 감소시킵니다. (문제가 해결되면 우선 순위를 다시 증가시킵니다.)"]
}

# 트러블 슈팅 명령어 데이터
trouble_shooting_data = {"명령어": ["show ip interface brief", "show vlan brief", "show spanning-tree", "show interfaces status", "show vrrp brief", "show standby brief"], 
                         "설명": ["인터페이스의 간단한 IP 정보 표시", "VLAN의 간단한 정보 표시", "스패닝 트리 프로토콜 설정 정보 표시", "인터페이스 상태 요약 표시", "VRRP(Virtual Router Redundancy Protocol) 인스턴스의 간단한 정보 표시", "HSRP(Hot Standby Router Protocol) 인스턴스의 간단한 정보 표시"]
}

# 이더채널 설정 명령어 데이터
etherchannel_data = {"명령어": ["int range [x/x-x]", "channel-group [x] mode [....]", "interface po[x]", "switchport mode access", "switchport access vlan 10", "no port-channel ~"], 
                     "설명": ["여러 포트를 한 번에 설정하기 위한 범위 선택", "이더채널 그룹 생성 및 모드 설정", "이더채널 포트 설정", "포트를 액세스 모드로 설정", "특정 VLAN에 포트 연결", "포트채널 삭제"]
}

# 라우티드 포트 설정 명령어 데이터
routed_port_data = {"명령어": ["interface [x/x]", "no switchport", "ip address x.x.x.x x.x.x.x", "ip routing"], 
                    "설명": ["인터페이스 연결", "스위치포트로 안 쓴다고 선언하여 라우티드 포트로 전환", "이 포트에 게이트웨이 설정", "라우팅 활성화"]
}

# SVI 설정 명령어 데이터
svi_data = {"명령어": ["interface vlan [vlan 번호]", "ip address [IP 주소] [서브넷 마스크]", "no shutdown"], 
            "설명": ["특정 VLAN에 접속하여 설정", "VLAN에 IP 주소와 서브넷 마스크 할당", "SVI 활성화"]
}

# HSRP(핫 스탠바이 라우팅 프로토콜) 설정 명령어 데이터
hsrp_data = {"명령어": ["interface vlan 10", "ip address 10.1.10.252 255.255.255.0", "standby 10 ip 10.1.10.254", "standby 10 preempt", "standby 10 priority 110", "standby [그룹명] timers ? ?", "", "show standby brief", "show standby"], 
             "설명": ["VLAN 10에 대한 인터페이스 설정을 시작", "VLAN 10에 IP 주소 10.1.10.252를 할당하고 서브넷 마스크를 255.255.255.0으로 설정", "가상 게이트웨이의 IP 주소를 10.1.10.254로 설정", "게이트웨이 장비가 다시 활성화될 때 자동으로 우선순위를 갖게 함", "가상 게이트웨이에 우선순위를 110으로 설정. 높은 우선순위를 갖는 장비가 active, 낮으면 standby","이중화된 기기들 끼리 정상 가동하는지 확인 (첫 숫자는 hello 타임, 둘째 숫자는 대기 시간)",  "", "간략한 가상 게이트웨이 정보 확인", "상세한 가상 게이트웨이 정보 확인"]
}

# VRRP Master/Worker 명령어 데이터
vrrp_data = {"명령어": ["interface vlan 10", "ip address 10.1.10.252 255.255.255.0", "vrrp10 ip 10.1.10.254", "vrrp 10 priority 110", "", "show vrrp brief", "show vrrp"], 
             "설명": ["VLAN 10 인터페이스 설정 시작", "VLAN 10에 IP 주소를 설정", "VRRP 그룹 10의 가상 IP 주소를 설정", "VRRP 그룹 10에서 우선순위를 110으로 설정(높은 값이 Active)", "", "간략한 VRRP 정보 표시", "상세한 VRRP 정보 표시"]
}

show_commands = {
    "명령어": ["show vlan", "show spanning-tree", "show ip route", "show running-config", "show interface", "show arp", "show history", "show vrrp", "show ip", "show access-lists", "show adjacency", "show authentication", "show bgp", "show cdp", "show cef", "show clock", "show configuration", "show connection", "show crypto", "show controllers", "show eigrp", "show environment", "show event-history", "show flash", "show hardware", "show hosts", "show idprom", "show ip access-lists", "show ip accounting", "show ip arp", "show ip dhcp", "show ip eigrp", "show ip igmp", "show ip interface", "show ip nat", "show ip ospf", "show ip rsvp", "show ipv6", "show license", "show line", "show logging", "show mac-address-table", "show multicast", "show network", "show policy-map", "show process", "show protocol", "show queueing", "show redundancy", "show router", "show sdm", "show session", "show snmp", "show ssh", "show stacks", "show startup-config", "show switch", "show tacacs+", "show tcp", "show tech-support", "show terminal", "show time", "show track", "show transceiver", "show version", "show voice", "show vpdn", "show vpn-sessiondb"],
    "설명": ["VLAN 정보 표시", "스패닝 트리 프로토콜 정보 표시", "IP 라우팅 정보 표시", "현재 실행 중인 설정 표시", "인터페이스 상태 및 설정 표시", "ARP 테이블 정보 표시", "명령어 이력 표시", "VRRP 정보 표시", "IP 프로토콜 정보 표시", "액세스 리스트 정보 표시", "인접 관계 정보 표시", "인증 상태 정보 표시", "BGP 정보 표시", "CDP 정보 표시", "CEF 정보 표시", "시계 설정 정보 표시", "현재 설정 표시", "접속 정보 표시", "암호화 설정 정보 표시", "컨트롤러 설정 정보 표시", "EIGRP 정보 표시", "환경 설정 정보 표시", "이벤트 히스토리 정보 표시", "플래시 메모리 정보 표시", "하드웨어 정보 표시", "호스트 정보 표시", "ID PROM 정보 표시", "IP 액세스 리스트 정보 표시", "IP 계정 정보 표시", "IP ARP 정보 표시", "IP DHCP 정보 표시", "IP EIGRP 정보 표시", "IP IGMP 정보 표시", "IP 인터페이스 정보 표시", "IP NAT 정보 표시", "IP OSPF 정보 표시", "IP RSVP 정보 표시", "IPv6 정보 표시", "라이센스 정보 표시", "라인 설정 정보 표시", "로그 정보 표시", "MAC 주소 테이블 정보 표시", "멀티캐스트 정보 표시", "네트워크 정보 표시", "정책 맵 정보 표시", "프로세스 정보 표시", "프로토콜 정보 표시", "큐잉 정보 표시", "중복 정보 표시", "라우터 정보 표시", "SDM 정보 표시", "세션 정보 표시", "SNMP 정보 표시", "SSH 정보 표시", "스택 정보 표시", "시작 설정 정보 표시", "스위치 상태 정보 표시", "TACACS+ 정보 표시", "TCP 정보 표시", "기술 지원 정보 표시", "터미널 설정 정보 표시", "시간 정보 표시", "트랙 정보 표시", "트랜시버 정보 표시", "버전 정보 표시", "음성 정보 표시", "VPDN 정보 표시", "VPN 세션 데이터베이스 정보 표시"]
}





#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------





# 기본설정 명령어
basic_df = pd.DataFrame(basic_data)

# vlan 설정 명령어
vlan_df = pd.DataFrame(vlan_data)

# VTP 설정 명령어
vtp_commands_df = pd.DataFrame(vtp_commands)

# 원격 접근 보안 설정 명령어
remote_access_df = pd.DataFrame(remote_access_data)

# 트렁크 프로토콜 설정 명령어
trunk_protocol_df = pd.DataFrame(trunk_protocol_data)

# 부트 이미지 변경 명령어
boot_image_change_df = pd.DataFrame(boot_image_change)

# 로그 저장 서버 명령어
bserver_logs_df = pd.DataFrame(server_logs)

# 원격 접속을 위한 스위치 IP 할당 명령어
remote_access_switch_df = pd.DataFrame(remote_access_switch)

# 트래킹 설정 명령어
tracking_commands_df = pd.DataFrame(tracking_commands)

# 트렁크 설정 명령어
trunk_protocol_commands_df = pd.DataFrame(trunk_protocol_commands)

# 네이티브 vlan 명령어
native_vlan_commands_df = pd.DataFrame(native_vlan_commands)

# STP 설정 명령어
stp_settings_df = pd.DataFrame(stp_settings)

# 루트 브릿지 보안 설정 명령어
root_bridge_security_df = pd.DataFrame(root_bridge_security)

# 트래킹 설정 명령어
tracking_data_df = pd.DataFrame(tracking_data)

# 트러블 슈팅 명령어
trouble_shooting_data_df = pd.DataFrame(trouble_shooting_data)

# 이더채널 설정 명령어
etherchannel_data_df = pd.DataFrame(etherchannel_data)

# 라우티드 포트 설정 명령어
routed_port_data_df = pd.DataFrame(routed_port_data)

# SVI 설정 명령어 데이터
svi_data_df = pd.DataFrame(svi_data)

# hsrp 설정 명령어 데이터
hsrp_data_df = pd.DataFrame(hsrp_data)

# VRRP Master/Worker 명령어 데이터
vrrp_data_df = pd.DataFrame(vrrp_data)

# show 명령어
show_commands_df = pd.DataFrame(show_commands)



#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------










# 테이블 데이터 정의
tables = {
"기본설정 명령어": basic_df,
"VLAN 설정 명령어": vlan_df,
"VTP 설정 명령어": vtp_commands_df,
"원격 접근 보안 설정 명령어": remote_access_df,
"트렁크 프로토콜 설정 명령어": trunk_protocol_df,
"부트 이미지 변경 명령어": boot_image_change_df,
"로그 저장 서버 명령어": bserver_logs_df,
"원격 접속을 위한 스위치 IP 할당 명령어": remote_access_switch_df,
"트래킹 설정 명령어": tracking_commands_df,
"트렁크 설정 명령어": trunk_protocol_commands_df,
"네이티브 VLAN 명령어": native_vlan_commands_df,
"STP 설정 명령어": stp_settings_df,
"STP 세부 설정 명령어": root_bridge_security_df,
"트래킹 설정 명령어": tracking_data_df,
"트러블 슈팅 명령어": trouble_shooting_data_df,
"이더채널 설정 명령어": etherchannel_data_df,
"라우티드 포트 설정 명령어": routed_port_data_df,
"SVI 설정 명령어": svi_data_df,
"HSRP 설정 명령어": hsrp_data_df,
"VRRP Master/Worker 명령어": vrrp_data_df,
"show 명령어":show_commands_df }
# 테이블 목록 표시
st.write('')
st.write('')


# 셀렉트 박스 옵션과 해당 내용들을 딕셔너리로 정의합니다.
options = {
    "라우터(Router)": "라우터는 네트워크에서 데이터를 전송하는 장비로, 다양한 네트워크 간의 패킷을 전달하는 역할을 합니다. 라우터는 패킷의 목적지를 확인하고 최적의 경로를 결정하여 해당 목적지로 패킷을 전달합니다.",
    "디폴트 라우팅(Default Routing)": "디폴트 라우팅은 라우터가 목적지를 알 수 없는 패킷을 처리하기 위해 사용됩니다. 라우터는 목적지 주소를 확인하고 라우팅 테이블에서 해당 목적지를 찾을 수 없을 때, 디폴트 라우트로 설정된 경로를 통해 패킷을 전달합니다.",
    "섬머리 라우팅(Summary Routing)": "섬머리 라우팅은 여러 개의 하위 네트워크를 하나의 대표적인 네트워크로 요약하여 라우터에게 전달하는 방식입니다. 이를 통해 라우팅 테이블의 크기를 줄이고 네트워크의 효율성을 향상시킵니다.",
    "라우터의 로드 밸런스(Router Load Balancing)": "라우터의 로드 밸런싱은 네트워크 트래픽을 균형 있게 분산시켜서 여러 경로를 통해 패킷을 전달하는 기술입니다. 이를 통해 네트워크 성능을 최적화하고 병목 현상을 예방할 수 있습니다.",
    "플로팅 스태틱 라우팅(Floating Static Routing)": "플로팅 스태틱 라우팅은 정적 라우팅의 대체 경로로 설정된 경로로 패킷을 전송하는 방법입니다. 주로 기본 경로가 다운되었을 때 백업 경로로 사용되며, 이를 통해 네트워크의 가용성을 높일 수 있습니다.",
    "롱기스트 매치 룰(Longest Match Rule)": "롱기스트 매치 룰은 라우터가 패킷의 목적지 주소를 검색할 때 가장 긴 매치를 찾아 해당 룰에 따라 패킷을 전달하는 기준입니다. 이를 통해 라우터는 라우팅 테이블에서 가장 구체적인 경로를 선택하여 최적의 경로로 패킷을 전송할 수 있습니다."
}



text = """
**스위치**는 네트워크에서 데이터를 전송하고 목적지MAC에 도달시켜주는 역할을 합니다.

스위치는 여러 장치들이 연결되어 있는 네트워크에서 데이터 흐름을 관리하며, 콜리전을 방지하여 원활한 통신을 돕습니다.  

이처럼, **스위치**는 네트워크에서 데이터 전송을 원활하게 하는 핵심 장비 중 하나입니다.
"""


#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------






#라우터

static_route_df = {
    "명령어": ["ip route [목적지 네트워크] [다음 홉 인터페이스] [다음 홉 라우터 IP] [AD 값]", "", "show ip route", "show ip route [목적지 IP]", "show ip route connected", "show ip route static"],
    "설명": ["처리하고 싶은 네트워크에 대한 정적 라우팅 설정", "", "라우터의 IP 라우팅 테이블 정보 확인", "특정 IP 주소로 가는 라우팅 경로 확인", "라우터에 연결된 네트워크 정보 확인", "직접 지정한 정적 라우트 정보 확인"]
}

# ip 연결 확인 명령어
ip_df = {
    "명령어": ["tracert", "trace router"],
    "설명": ["PC에서 연결 확인", "라우터에서 연결 확인"]
}

#OSPF 명령어
ospf_commands = {
    "명령어": ["router ospf <아이디>", 
            "network x.x.x.x <wildcard_mask> area <구역번호>",
            "router-id x.x.x.x", "clear ip ospf process", 
            "", 
            "ip ospf cost", 
            "auto-cost reference-bandwidth <value>", 
            "ip ospf network point-to-point", 
            "", 
            "default-information originate", 
            "default-information originate always", 
            "neighbor <ip> default-originate", 
            "", 
            "passive-interfce <인터페이스>", 
            "passive-interface default", 
            "no passive-interface <인터페이스>", 
            "", 
            "redistribute [재분배 할 프로토콜 명] [프로토콜ID] metric [값]", 
            "redistribute <재분배 대상 프로토콜> subnets", 
            "redistribute <재분배 대상> subnets metric-type <타입번호>",
            "", 
            "show ip ospf neighbor", 
            "show ip protocols", 
            "show ip route ospf", 
            "show run | section ospf", 
            "show ip ospf interface brief", 
            "show ip ospf database"],
    "설명": ["ospf를 실행 후 아이디 번호를 지정(본인만 인지함)", 
           "x.x.x.x = 내 hello 메세지 보낼 인터페이스 IP | 와일드카드 마스크 | 연결할 구역번호", 
           "라우터ID 변경 명령어 (IP 형식의 ID지만 통신과는 상관 없음)", 
           "라우터ID 변경을 리셋으로 적용", 
           "", 
           "OSPF cost 변경 명령어", 
           "OSPF에서 자동 비용 계산에 사용되는 참조 대역폭 설정", 
           "인터페이스를 P2P상태로 변경 (DR/BDR선정x)", 
           "", 
           "라우팅 테이블에 Default Route가 있는 경우 광고", 
           "라우팅 테이블에 Default Route가 없어도 광고", 
           "특정 Neighbor에게 Default Route가 나라고 광고", 
           "", 
           "이 방향으로는 Hello메세지를 보내지 말라는 명령어(광고는 실행함)", 
           "모든 인터페이스에 Hello메세지를 보내지 않음", 
           "이 인터페이스는 Hello 메세지를 보냄", 
           "", 
           "재분배 할 프로토콜을 명시하고 어떤 값으로 변경할 것인지 입력", 
           "재분배 대상 프로토콜의 라우팅 테이블을 재분배하여 가져오는 명령어 (subnets를 써야 서브넷 값까지 가져옴)", 
           "재분배 대상의 타입을 결정하여 재분배", 
           "", 
           "OSPF 이웃 목록 표시", 
           "라우팅 프로토콜 설정과 관련된 정보 표시", 
           "OSPF로 학습한 라우팅 테이블 표시", 
           "현재 라우터의 구성에서 OSPF 구성 섹션 표시", 
           "OSPF 인터페이스의 간략한 상태 표시", 
           "OSPF 데이터베이스 정보 표시"]
}

#show 명령어
show = {
    "명령어": ["show ip route", "show ip route [목적지 IP]", "show ip route connected", "show ip route static", "show ip ospf neighbor", "show ip protocols"],
    "설명": ["라우터의 IP 테이블 정보 확인", "특정 IP 주소로 가는 경로 확인", "라우터에 연결된 네트워크 정보 확인", "스태틱 라우트 정보 확인", "라우터의 네이버 관계 확인", "라우터의 프로토콜 아이디 확인"]
}


#standard_ACL
standard_ACL = {
    "명령어": ["access-list <Standard ACL> <permit/deny> <source IP> <와일드카드 마스크>", "access-list <Standard ACL> <permit/deny> host <host IP>", "" , "ip access-group <Standard ACL> <in/out>", "access-class <Standard ACL> <in/out>", "distribute-list <Standard ACL> <in/out>", "", "show access-lists"],
    "설명": ["특정 소스 IP 주소를 허용/거부하는 ACL을 생성.", "ACL의 특정 호스트만 트래픽 <허용/거부>(Classification).", "", "생성한 ACL을 인터페이스에 적용하여 in/out바운드로 활성화.", "원격 접속 허용 여부 리스트 활성화.", "OSPF에 ACL 적용.", "", "현재 적용된 ACL 목록 및 규칙을 확인."]
}

# Extended_ACL
Extended_ACL = {
    "명령어": ["access-list <확장 ACL> <permit/deny> <port num> <source IP> <Wildcard> <Dest IP> equal <port num>" , "", "access-list <Extended ACL> <permit/deny> <source IP x.x.x.x> <Wildcard mask x.x.x.x> equal <Port Num>", "access-list <ACL번호> deny any any log",  "no <rule num>", "", "ip access-list extended <이름>"],
    "설명":["확장 access-list생성 후 출발 & 목적지 IP와 포트를 정하여 허용/거부 설정", "", "확장 ACL 리스트 작성", "모든 트래픽 거부 설정 후 드랍된 트래픽 로그를 저장하도록 함", "리스트에 들어가 삭제할 정책의 번호 기입(삭제기능)", "", "이름을 가진 ACL 생성. (생성 후 NACL로 들어가지며 리스트 작성 시 ACL명을 입력 안 해도 됨"]
}

# eBGP
eBGP = {
    "명령어":["router bgp <Local AS-num>","neighbor <상대IP> remote-as <상대 as-num>","neighbor <IP주소> password <비밀번호>","network <광고할 IP> mask <서브넷 마스크>","", "show ip bgp summary", "show ip bgp", "show ip bgp <도착지 IP>"],
    "설명":["Local AS 번호를 입력하여 경계 게이트웨이 프로토콜(BGP) 작동", "Neighbor를 맺고 싶은 상대의 IP와 AS를 입력하여 Neighbor 관계 요청", "Neighbor를 맺을 때 설정할 비밀번호", "광고하고 싶은 IP를 테이블에 등록", "", "BGP 이웃 관계 상세 정보 확인", "BGP 테이블 정보 확인", "BGP 테이블에서 도착지로 가는 경로 확인"]
}

#iBGP
iBGP = {
    "명령어":["router bgp <Local AS-num>", "neighbor <상대 Loopback IP> remote-as <상대 as-num>", "neighbor <상대 Loopback IP> update-source <내 Loopback 인터페이스>", "ip route <summary> <mask> null 0", "nighbor <iBGP Neighbor IP> next-hop-self", "neighbor <Neighbor IP> route-reflector-client", "", "show ip bgp summary", "show ip bgp", "show ip bgp <도착지 IP>","", "OSPF Nighbor"],
    "설명":["Local AS 번호를 입력하여 경계 게이트웨이 프로토콜(BGP) 작동", "Neighbor를 맺고 싶은 상대의 Loopback IP와 AS를 입력하여 Neighbor 관계 요청", "내 소스 IP를 Loopback으로 수정하고 상대의Loopback IP를 통해 iBGP 이웃 관계를 맺는 설정.", "광고하려는 라우터에서 빈 공간에 축약 라우팅 정보 등록(null 0 자료 참고)", "eBGP 역할을 하는 라우터의 iBGP 설정 (Next-Hop Self 자료 참고)", "RR 기기에서 RRC 지정(RRC는 RR과 네이버만 맺으면 됨)", "", "BGP 이웃 관계 상세 정보 확인", "BGP 테이블 정보 확인", "BGP 테이블에서 도착지로 가는 경로 확인","", "OSPF로 경로와 Loopback IP를 광고해야 함"]
}

in_NAT_commands = {
    "명령어": ["ip nat inside", "ip nat outside", "ip nat inside source static <사설IP> <공인IP>", "", "show ip nat translations"],
    "설명": ["해당 인터페이스를 내부 네트워크로 지정", "해당 인터페이스를 외부 네트워크로 지정", "내부에서 외부로 나가는 패킷의 출발지 IP 주소를 사설 IP에서 공인 IP로 변경", "", "NAT 테이블에서 IP 변환을 보여줌"]
}

out_NAT_commands = {
    "명령어": ["ip nat inside", "ip nat outside", "ip nat outside source static <공인IP> <사설IP>", "", "show ip nat translations"],
    "설명": ["해당 인터페이스를 내부 네트워크로 지정", "해당 인터페이스를 외부 네트워크로 지정", "외부에서 내부로 들어오는 패킷의 출발지 IP 주소를 공인 IP에서 사설 IP로 변경", "", "NAT 테이블에서 IP 변환을 보여줌"]
}

D_NAT_commands = {
    "명령어": ["ip nat pool <Pool이름> <공인IP시작> <공인IP끝> prefix-length 24", "access-list 1 permit <IP주소> <wildcard>", "ip nat inside source list 1 pool <Pool이름>", "", "show ip nat translations"],
    "설명": ["NAT Pool에 지정된 범위 내의 공인 IP 주소를 여러 개 저장.", "ACL1을 사용하여 NAT를 적용할 네트워크를 정의.", "ACL1에 일치하는 주소를 가지는 패킷들은 NAT inside에서 지정된 Pool을 공유하도록 설정.", "", "NAT 테이블에서 IP 변환을 보여줌."]
}

PAT_commands = {
    "명령어": ["ip nat inside", "ip nat outside", "access-list 1 permit <IP주소> <wildcard>", "ip nat inside source list 1 interface fastEthernet 1/0 overload", "", "show ip nat translations"],
    "설명": ["해당 인터페이스를 내부 네트워크로 지정", "해당 인터페이스를 외부 네트워크로 지정", "ACL1을 사용하여 NAT를 적용할 네트워크를 정의.", "inside에서 올라오는 IP가 ACL1과 일치하면 fastEthernet 1/0의 IP로 덮어 씌움(overload)", "", "NAT 테이블에서 IP 변환을 보여줌."]
}

bgp_Wight_commands = {
    "명령어": [
        "(config-router)# neighbor 192.168.13.3 route-map SETWEIGHT in",
        "(config)# access-list 1 permit 22.22.22.0 0.0.0.255",
        "(config)# route-map SETWEIGHT permit 10",
        "(config-route-map)# match ip address 1",
        "(config-route-map)# set weight 400",
        "(config)# route-map SETWEIGHT permit 20",
        "(config-route-map)# set weight 0",
        "# clear ip bgp *",
        "Neighbor의 모든 경로에 적용(Global) 시",
        "(config-router)# neighbor <IP> weight <Num>"
    ],
    "설명": [
        "192.168.13.3 네이버에서 들어오는 경로에 'SETWEIGHT' Route Map 적용 선언(inbound).",
        "ACL 1 생성, 22.22.22.0/24 네트워크 허용.",
        "Route Map 'SETWEIGHT' 생성, 순서 10.",
        "ACL 1에 매칭되는 IP 주소를 선택.",
        "매칭되는 경로의 weight를 400으로 설정.",
        "Route Map 'SETWEIGHT'에 추가 조건, 순서 20.",
        "나머지 경로의 weight를 0으로 설정.",
        "BGP 테이블 삭제 후 재생성.",
        "",
        "네이버의 Weight 값을 지정"
    ]
}

bgp_local_preference_commands = {
    "명령어": [
        "(config)# route-map <NAME> permit 10",
        "(config-route-map)# set local-preference <100이상의 값>",
        "(config-router)# neighbor <IP> route-map <NAME> in",
        "Neighbor의 모든 경로에 적용(Global) 시",
        "(config-router)# bgp default local-preference <Num>"
    ],
    "설명": [
        "라우터 맵의 10번 규칙을 생성.",
        "Local Preference 값을 100 이상의 값으로 지정. (기본값은 100)",
        "이 네이버로 들어오는 경로들의 Local Preference 값을 이 라우터 맵과 같게 지정.",
        "",
        "BGP의 기본 Local Preference를 지정."
    ]
}

as_path_prepend_commands = {
    "명령어": [
        "(config)# route-map <NAME> permit 10",
        "(config-route-map)# set as-path prepend 1 1 1 1 1",
        "(config-router)# neighbor <IP> route-map <NAME> out"
    ],
    "설명": [
        "Route Map의 10번 정책 생성.",
        "AS-Path 값에 1 1 1 1 1을 추가하는 정책 생성.",
        "이 네이버에게 경로를 전달할 때 AS Path 값을 Route-Map과 같게하여 전달."
    ]
}


metric_commands = {
    "명령어": [
        "(config)# route-map <NAME> permit 10",
        "(config-route-map)# set metric <Num>",
        "(config-router)# neighbor <IP> route-map <NAME> out"
    ],
    "설명": [
        "Route Map의 10번 정책 생성.",
        "메트릭 값 지정.",
        "iBGP Neighbor에게 나의 MED 값을 route-map의 값으로 설정하여 전파."
    ]
}

















# 테이블 데이터 정의
r_tables = {"스태틱 라우팅 명령어": static_route_df,
           "OSPF(Open Shortest Path First) 명령어": ospf_commands,
           "standard_ACL 명령어": standard_ACL,
           "Extended_ACL 명령어":Extended_ACL,
            "External Border Gateway Protocol 명령어 (외부 경계 게이트웨이 프로토콜)" : eBGP,
            "Internal Border Gateway Protocol 명령어 (내부 경계 게이트웨이 프로토콜)": iBGP,
            "BGP Attribute의 Weight 값 조정(경로 조정) 명령어(나가는 트래픽을 특정 경로로 보내는 명령어)": bgp_Wight_commands,
            "BGP Attribute의 local_preference 값 조정(경로 조정) 명령어(나가는 트래픽을 특정 경로로 보내는 명령어)": bgp_local_preference_commands,
            "BGP Attribute의 AS_Path 값 조정(경로 조정) 명령어 (들어오는 트래픽 우회용 명령어)": as_path_prepend_commands,
            "BGP Attribute의 MED 값 조정(경로 조정) 명령어 (들어오는 트래픽 우회용 명령어)": metric_commands,
            "Inside Static NAT 명령어": in_NAT_commands,
            "Outside Static NAT 명령어": out_NAT_commands,
            "Dynamic NAT 명령어": D_NAT_commands,
            "PAT 명령어": PAT_commands,
            "ip 연결 확인 명령어": ip_df,
           "show 명령어": show}





















#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------




#방화벽


text3 = """
💡 **방화벽 (Firewall)**


내부와 외부 네트워크 사이에 존재하는 보안 장벽.
상태 정보 필터링을 사용해 모든 IN/OUT 연결을 추적 함.

Deep Packet Inspection으로 L2~L7 데이터까지 모두 확인 가능.

Zone Base로 작동. (Inside[High Level] = LAN | outside[Low Level] = WAN) 
시큐리티 레벨이 높은 곳에서 아래로는 데이터를 허용하지만 그 반대로는 불가.
패킷이 High Level에서 나갈 때 패킷 정보가 기록되어 되돌아올 때의 설정이 필요 X.
"""

text4 = """
💡 **ASA의 ACL**

L3모드에서만 사용 가능.
Classification 용도로만 사용 가능. (filtering 용도 사용 불가)
Named-ACL만 사용 가능.

ACL은 방화벽보다 상위 프로토콜.

</aside>ASA의 ACL

L3모드에서만 사용 가능.
Classification 용도로만 사용 가능. (filtering 용도 사용 불가)
Named-ACL만 사용 가능.

ACL은 방화벽보다 상위 프로토콜.
"""


# ip 연결 확인 명령어
f_command = {
    "명령어": [
        "firewall transparent",
        "",
        "show ip address",
        "show run interface",
        "show interface ip brief",
        "show nameif",
        "show firewall",

    ],
    "설명": [
        "인터페이스를 L3에서 L2모드로 전환",
        "",
        "인터페이스의 IP 정보 확인",
        "인터페이스의 부팅 명령어 확인",
        "인터페이스들의 상태 확인",
        "방화벽 Zone의 이름과 Security Level 확인",
        "인터페이스가 L2 또는 L3로 동작하는지 확인",

    ]
}

L3_command = {
    "명령어": [
        "route <nameif> <dest IP> <Wmask> <Next hop>",
        "",
        "show route",
        "show run route"
    ],
    "설명": [
        "스태틱 라우팅 (interface name을 넣어줘야 함)",
        "",
        "라우팅 테이블 확인",
        "동작 중인 라우트 정보 확인"
    ]
}


OSPF_command = {
    "명령어": [
        "network <IP> <netmask> <area>",
        "default-information originate [always]",
        "",
        "show run router ospf"
    ],
    "설명": [
        "OSPF에 네트워크 광고",
        "기본 게이트웨이 지정",
        "",
        "OSPF에서 실행 중인 라우팅 정보 확인"
    ]
}


SSH_command = {
    "명령어": [
        "(config)# username <name> password <password>",
        "(config)# aaa authentication ssh console LOCAL",
        "(config)# crypto key generate rsa modules 1024",
        "(config)# ssh <IP> <netmask> <nameif>",
        "R1# ssh -l <username> <IP>"
    ],
    "설명": [
        "ID와 Password 설정",
        "SSH와 콘솔 접근 시 이 장비에서 설정한 ID/Password로 인증하는 선언",
        "키를 생성하고 정보를 암호화",
        "IP와 nameif가 일치하는 사용자는 접속을 허용",
        "SSH 접근 명령어"
    ]
}


NameIF_command = {
    "명령어": [
        "(config-if)#nameif <name>",
        "(config-if)#ip address <IP> <netmask>",
        "(config-if)#security-level <1~100>",
        "(config-if)#same-security-traffic permit inter-interface",
        "(config-if)#no shutdown"
    ],
    "설명": [
        "NameIF 설정 (<INSIDE 사용 시 Level 100 사용>) (NameIF는 고유해야 함)",
        "인터페이스 IP 지정",
        "Security Level 수동 지정",
        "같은 Security Level을 가진 Zone끼리의 통신을 허용",
        "인터페이스 활성화"
    ]
}

ASDM_command = {
    "명령어": [
        "asdm image disk0:/asdm-731.bin",
        "http server enable",
        "http <IP> <netmask> <nameif>",
        "username <username> password <password> privilege 15"
    ],
    "설명": [
        "ASDM 이미지 지정",
        "HTTP 서버 활성화",
        "HTTP 접근 인터페이스 IP 지정",
        "사용자 계정 생성 (권한 레벨 15)"
    ]
}

C_Table_command = {
    "명령어": [
        "policy-map global_policy",
        "class inspection_default",
        "inspect icmp",
        "",
        "show conn",
        "show conn all",
        "show conn all detail"
    ],
    "설명": [
        "전역 정책 맵을 설정",
        "기본 검사 클래스를 설정",
        "ICMP 패킷을 검사하고 필터링",
        "",
        "현재 활성화된 연결 테이블을 확인",
        "모든 연결 테이블 확인",
        "모든 연결 테이블 상세 정보 확인"
    ]
}

F_ACL_command = {
    "명령어": [
        "(config)# access-list INSIDE_INBOUND deny tcp any host 192.168.2.2 eq 80",
        "(config)# access-group INSIDE_INBOUND in interface INSIDE"
    ],
    "설명": [
        "TCP 통신하는 모든 Src IP가 192.168.2.2로 향하면서 포트가 80과 같다면 차단",
        "“INSIDE_INBOUND” ACL을 “INSIDE” NameIF를 가진 인터페이스에서 올라올 때 적용"
    ]
}

object_command = {
    "명령어": [
        "object <Type> <Name>",
        "",
        "show run object"
    ],
    "설명": [
        "오브젝트 타입과 이름 생성(단일 개체만 지정 가능)",
        "",
        "생성한 오브젝트 확인"
    ]
}

object_group_command = {
    "명령어": [
        "object-group <Type> <Name>",
        "access-list <ACL Name> <P/D> <L4> <sIP> object-group <OG Name> eq <Port Num>",
        "",
        "show run object-group"
    ],
    "설명": [
        "오브젝트 그룹을 생성하는 명령어",
        "오브젝트 그룹을 이용하여 ACL 적용",
        "",
        "생성한 오브젝트 그룹 확인"
    ]
}
dynamic_object_nat_command = {
    "명령어": [
        "object network PUBLIC_POOL",
        "range 192.168.2.100 192.168.2.200",
        "object network INTERNAL",
        "subnet 192.168.1.0 255.255.255.0",
        "nat (<inside>, <outside>) dynamic PUBLIC_POOL interface",
        "",
        "show nat",
        "show xlate"
    ],
    "설명": [
        "외부 IP 주소 범위를 정의하는 객체를 생성하거나 설정하는 명령어.",
        "퍼블릭 IP 풀 오브젝트화.",
        "내부 네트워크를 정의하는 객체를 생성하거나 설정하는 명령어.",
        "내부 네트워크 오브젝트화.",
        "<inside>에서<outside>로 향하는 트래픽을 PUBLIC_POOL로 NAT 하고, 풀을 모두 사용하면 내 인터페이스를 PAT로 사용하여 통신하게 한다.",
        "",
        "NAT 정책 및 동작 확인.",
        "NAT 변환 세부 현황 확인."
    ]
}

static_object_nat_pat_command = {
    "명령어": [
        "object network WEB_SERVER",
        "host 192.168.1.1",
        "nat (DMZ,OUTSIDE) static 192.168.2.200"
    ],
    "설명": [
        "웹 서버를 정의하는 객체를 생성하거나 설정하는 명령어.",
        "웹 서버의 내부 IP 주소를 설정하는 명령어.",
        "DMZ 영역과 외부 네트워크 간의 통신에서 웹 서버의 내부 IP 주소를 192.168.2.200으로 정적으로 변환하는 명령어."
    ]
}
manual_dynamic_nat_command = {
    "명령어": [
        "nat (inside,outside) source dynamic inside_real inside_mapped destination static outside_real outside_real"
    ],
    "설명": [
        "<inside>에서 <outside>로 나갈 때, src인 inside_real>을 <inside_mapped>로 dynamic하게 NAT하는데 dest가 <outside_real> <outside_real>일때 NAT 하겠다."
    ]
}
manual_dynamic_pat_command = {
    "명령어": [
        "nat (inside,outside) source dynamic inside_real interface destination static outside_real outside_real"
    ],
    "설명": [
        "<inside>에서 <outside>로 나갈 때 src인 <inside_real>을 Interface로 dynamic하게 PAT하는데 dest가 <outside_real> <outside_real>일때 PAT 하겠다."
    ]
}
failover_commands = {
    "명령어": [
        "failover lan unit <primary/secondary>",
        "failover lan interface <FAILOVER> Ethernet 0/3",
        "failover link <FAILOVER> Ethernet 0/3",
        "failover interface ip FAILOVER 192.168.12.1 255.255.255.0 standby 192.168.12.2",
        "failover",
        "ip address 192.168.1.254 255.255.255.0 standby 192.168.1.253",
        "",
        "prompt hostname priority state",
        "no failover active",
        "no monitor-interface outside",
        "",
        "show failover history",
        "show failover"
    ],
    "설명": [
        "Primary/Secondary 장비 선정",
        "상태체크 링크에 이름 부여",
        "상태 및 동기화 링크에 이름 부여",
        "Active/Standby 인터페이스에 게이트웨이 IP 부여(두 장비 동일하게)",
        "Failover(이중화) 활성화",
        "인터페이스에 NameIF와 IP를 설정할 때 Standby IP도 함께 입력",
        "",
        "프롬프트에 Failover 역할 표시",
        "active를 비활성화 하여 이중화 테스트",
        "outside 인터페이스를 모니터링하지 않는다는 명령어",
        "",
        "failover 동작 히스토리 확인",
        "failover 정보 확인"
    ]
}

# 테이블 데이터 정의
F_tables = {"방화벽 기본 명령어": f_command,
           "L3 명령어": L3_command,
            "OSPF 명령어": OSPF_command,
            "SSH 명령어": SSH_command,
            "NameIF 명령어": NameIF_command,
            "ASDM 이미지 다운로드 명령어": ASDM_command,
            "Connect Table 명령어": C_Table_command,
            "ACL 명령어": F_ACL_command,
            "오브젝트 명령어": object_command,
            "오브젝트 그룹 명령어": object_group_command,
            "다이나믹 오브젝트 NAT 명령어 (섹션2)": dynamic_object_nat_command,
            "스태틱 오브젝트 NAT/PAT 명령어 (섹션2)": static_object_nat_pat_command,
            "매뉴얼 다이나믹 NAT 명령어 (섹션1)": manual_dynamic_nat_command,
            "매뉴얼 다이나믹 PAT 명령어 (섹션1)": manual_dynamic_pat_command,
            "failover(이중화)명령어": failover_commands
           }





#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#VPN

VPN_LIST = ["GRE 명령어", 
            "IPsec 명령어",  
            "IPsec 기본 명령어", 
            "IPsec Dynamic Crypto Map 명령어", 
            "GRE over IPsec 명령어", 
            "IPsec VTI 명령어 (Virtual Tunnel Interface)",
           "ASA_IPsec_VPN 명령어"]

network_commands = {
    "GRE 명령어": {
        "GRE 명령어": pd.DataFrame({
            "명령어": [
                "(config)#interface tunnel <Tunnel Num>",
                "(config-if)#tunnel source <SIP or IF>",
                "(config-if)#tunnel destination <DIP>",
                "(config-if)#ip address <IP> <Netmask>",
                "(config-if)#tunnel key <Num>",
                "(config-if)#keepalive <Num>",
                "",
                "show interfaces tunnel <Tunnel Num>",
                "",
                "(config)#router ospf 1",
                "(config-router)#network <T SIP> <Net mask> area 0"
            ],
            "설명": [
                "터널 인터페이스 생성",
                "터널 Src IP로 사용할 IF 또는 IP 지정",
                "터널 Dest IP 입력",
                "터널의 논리적 IF의 IP 지정. 양쪽이 동일한 NET을 가져야 함",
                "터널의 키 값 지정(양쪽이 동일해야 함)",
                "Health Check 메세지 초 지정",
                "",
                "터널 정보 확인",
                "",
                "OSPF 라우터 구성",
                "터널의 IP로 IGP를 통해 지사 간 Neighbor P2P 연결"
            ]
        })
    },
    "IPsec 명령어": {
        "[Phase1] ISAKMP SA 생성": pd.DataFrame({
            "명령어": [
                "(config)#crypto isakmp policy 1",
                "(config-isakmp)#encryption aes",
                "(config-isakmp)#hash sha",
                "(config-isakmp)#authentication pre-share",
                "(config-isakmp)#group 2",
                "(config)#crypto isakmp key 0 <MYPASSWORD> address <상대 라우터 퍼블릭 인터페이스 IP>"
            ],
            "설명": [
                "ISAKMP 정책을 설정 (번호 1 사용)",
                "암호화 알고리즘으로 AES를 선택",
                "해시 알고리즘으로 SHA를 선택",
                "사전 공유된 키를 사용하여 인증을 설정",
                "Diffie-Hellman 그룹 번호를 설정 (그룹 2는 비교적 보안 수준이 높고 효율적인 그룹)",
                "특정 IP 주소에 대한 ISAKMP 사전 Pre-Shared Key(사전 공유 키)를 설정"
            ]
        }),
        "[Phase2] IPsec SA 생성": pd.DataFrame({
            "명령어": [
                "(config)#crypto ipsec transform-set <MYTRANSFORMSET> esp-aes esp-sha-hmac"
            ],
            "설명": [
                "IPSec 변환 세트를 정의. 이 세트는 데이터를 암호화하는 데 사용되며 AES 암호화 및 SHA 해시를 사용"
            ]
        }),
    "[Phase3] Crypto MAP 생성 및 적용": pd.DataFrame({
            "명령어": [
                "(config)#crypto map <CRYPTOMAP> 10 ipsec-isakmp",
                "(config-crypto-map)#set peer <상대 라우터 퍼블릭 인터페이스 IP>",
                "(config-crypto-map)#set transform-set <MYTRANSFORMSET>",
                "(config-crypto-map)#match address 100",
                "(config-crypto-map)#reverse-route",
                "(config)#access-list 100 permit ip host <내 호스트IP> host <상대 호스트 IP>",
                "(config)#interface <Interface>",
                "(config-if)#crypto map <CRYPTOMAP>"
            ],
            "설명": [
                "IPsec 및 ISAKMP를 위한 crypto 맵 설정. 맵 번호는 10. (crypto map은 하나의 이름만 사용)",
                "VPN 터널의 대상 피어를 설정",
                "전에 설정한 IPsec 변환 세트 적용",
                "암호화 및 인증을 위해 적용할 ACL을 지정. 여기서는 ACL 100",
                "대상에 대한 Static Route 자동 생성",
                "ACL 100을 생성하여 IPSec 터널을 통해 통신 할 IP 선정. (Out Bound 방식)",
                "VPN 설정을 적용할 네트워크 인터페이스 선택.",
                "인터페이스에 VPN 설정을 적용."
            ]
        })
    },
    
    "IPsec 기본 명령어": {
        "IPsec 기본 명령어": pd.DataFrame({
            "명령어": [
                "통신 시도",
                "show crypto ipsec sa",
                "show crypto isakmp sa",
                "clear crypto isakmp",
                "clear crypto sa"
            ],
            "설명": [
                "통신 시도로 인해 터널 생성",
                "IPSec 터널의 암호화 및 복호화 횟수 확인",
                "ISAKMP 터널 테이블 확인",
                "ISAKMP 터널 삭제",
                "IPSec 터널 삭제"
            ]
        })
    },
    "IPsec Dynamic Crypto Map 명령어": {
        "[Phase1] ISAKMP SA 생성" : pd.DataFrame({
            "명령어": [
                "(config)# crypto isakmp policy 10",
                "(config-isakmp)# encryption 3des",
                "(config-isakmp)# authentication pre-share",
                "(config-isakmp)# hash md5",
                "(config-isakmp)# group 2",
                "(config)# crypto isakmp key cisco address 0.0.0.0 0.0.0.0"
            ],
            "설명": [
                "IKE 정책 설정 (정책 번호 10)",
                "3DES 암호화 알고리즘 설정",
                "사전 공유 키 방식의 인증 설정",
                "MD5 해시 알고리즘 설정",
                "Diffie-Hellman 그룹 번호 설정 (그룹 2)",
                "사전 공유 키 지정 및 대상 주소 설정"
            ]
        }),
        
        "[Phase2] IPsec SA 생성" : pd.DataFrame({
            "명령어": [
                "(config)# ip access-list extended <ACL 이름>",
                "(config-ext-nacl)# permit ip <sIP> <Wmask> <dIP> <Wmask>",
                "(config)# crypto ipsec transform-set <PHASE2> esp-aes esp-sha-hmac"
            ],
            "설명": [
                "확장된 IP 접근 목록을 설정",
                "내부 특정 IP 주소 및 서브넷간의 통신을 허용하는 ACL 규칙을 추가",
                "IPSec 변환 세트를 정의. AES 암호화 및 SHA 해시를 사용"
            ]
        }),
        
        "[Phase3] Dynamic Crypto MAP생성 및 적용" : pd.DataFrame({
            "명령어": [
                "(config)# crypto dynamic-map <DMAP> 10",
                "(config-crypto-map)# match address <ACL 이름>",
                "(config-crypto-map)# set transform-set <PHASE2>",
                "(config)# crypto map <VPN> 10 ipsec-isakmp dynamic <DMAP>",
                "(config)# interface <Interface>",
                "(config-subif)# crypto map <VPN>"
            ],
            "설명": [
                "동적 맵을 설정. <DMAP>은 사용자가 정의한 이름으로 대체되어야 함",
                "ACL 이름을 사용하여 트래픽 일치 조건을 설정",
                "변환 세트를 설정하여 IPSec 정책을 적용. <PHASE2>는 사용자가 정의한 이름으로 대체되어야 함",
                "IPSec 터널을 설정하고 동적 맵을 사용하여 정책을 적용. <VPN>은 사용자가 정의한 이름으로 대체되어야 함",
                "인터페이스 설정 모드로 이동. <Interface>는 설정할 인터페이스의 이름",
                "인터페이스에 IPSec VPN을 적용하기 위해 VPN 맵을 적용. <VPN>은 이전에 정의한 VPN 맵의 이름"
            ]
        })
    },
    "GRE over IPsec 명령어": {
        "[Phase1] GRE 명령어" : pd.DataFrame({
            "명령어": [
                "(config)#interface tunnel <Tunnel Num>",
                "(config-if)#tunnel source <SIP or IF>",
                "(config-if)#tunnel destination <DIP>",
                "(config-if)#ip address <IP> <Netmask>",
                "(config-if)#tunnel key <Num>",
                "(config-if)#keepalive <Num>",
                "show interfaces tunnel <Tunnel Num>",
                "(config)#router ospf 1",
                "(config-router)#network <T SIP> <Net mask> area 0>"
            ],
            "설명": [
                "터널 인터페이스 생성",
                "터널 Src IP로 사용할 IF 또는 IP 지정",
                "터널 Dest IP 입력",
                "터널의 논리적 IF의 IP 지정. 양쪽이 동일한 NET을 가져야 함",
                "터널의 키 값 지정 (양쪽이 동일해야 함)",
                "Health Check 메세지 초 지정",
                "터널 정보 확인",
                "OSPF 생성",
                "Tunnel의 IP로 IGP를 통해 지사 간 Neighbor P2P 연결"
            ]
        }),
        
        
        "[Phase2] ISAKMP SA 생성" : pd.DataFrame({
            "명령어": [
                "(config)#crypto isakmp policy 1",
                "(config-isakmp)#encryption aes",
                "(config-isakmp)#hash sha",
                "(config-isakmp)#authentication pre-share",
                "(config-isakmp)#group 2",
                "(config)#crypto isakmp key 0 <MYPASSWORD> address <상대 라우터 퍼블릭 인터페이스 IP>"
            ],
            "설명": [
                "ISAKMP 정책을 설정 (번호 1 사용)",
                "암호화 알고리즘으로 AES를 선택",
                "해시 알고리즘으로 SHA를 선택",
                "사전 공유된 키를 사용하여 인증을 설정",
                "Diffie-Hellman 그룹 번호를 설정 (그룹 2는 비교적 보안 수준이 높고 효율적인 그룹)",
                "특정 IP 주소에 대한 ISAKMP 사전 Pre-Shared Key(사전 공유 키)를 설정"
            ]
        }),
        
        "[Phase3] IPsec SA 생성" : pd.DataFrame({
            "명령어": [
                "(config)#crypto ipsec transform-set <MYTRANSFORMSET> esp-aes esp-sha-hmac"
            ],
            "설명": [
                "IPSec 변환 세트를 정의. 이 세트는 데이터를 암호화하는 데 사용되며 AES 암호화 및 SHA 해시를 사용"
            ]
        }),
        
        "[Phase4] Crypto MAP 생성 및 적용": pd.DataFrame({
            "명령어": [
                "(config)#crypto map <CRYPTOMAP> 10 ipsec-isakmp",
                "(config-crypto-map)#set peer <상대 라우터 퍼블릭 인터페이스 IP>",
                "(config-crypto-map)#set transform-set <MYTRANSFORMSET>",
                "(config-crypto-map)#match address 100",
                "(config-crypto-map)#reverse-route",
                "(config)#access-list 100 permit ip host <내 호스트IP> host <상대 호스트 IP>",
                "(config)#interface <Interface>",
                "(config-if)#crypto map <CRYPTOMAP>"
            ],
            "설명": [
                "IPsec 및 ISAKMP를 위한 crypto 맵을 설정. 맵 번호는 10. (crypto map은 하나의 이름만 사용)",
                "VPN 터널의 대상 피어를 설정",
                "전에 설정한 IPsec 변환 세트 적용",
                "암호화 및 인증을 위해 적용할 ACL을 지정. 여기서는 ACL 100. (GRE가 먼저 적용되기 때문에 GRE의 IP를 지정해야 함)",
                "대상에 대한 Static Route 자동 생성",
                "ACL 100을 생성하여 IPSec 터널을 통해 통신 할 IP 선정. (Out Bound 방식)",
                "VPN 설정을 적용할 네트워크 인터페이스 선택.",
                "인터페이스에 VPN 설정을 적용."
            ]
        }),
        
        "GRE over IPsec 확인": pd.DataFrame({
            "명령어": [
                "ping 통신 시도",
                "show crypto ipsec sa",
                "show crypto isakmp sa",
                "clear crypto isakmp",
                "clear crypto sa"
            ],
            "설명": [
                "통신 시도로 인해 터널 생성",
                "IPSec 터널의 암호화 및 복호화 횟수 확인",
                "ISAKMP 터널 테이블 확인",
                "ISAKMP 터널 삭제",
                "IPSec 터널 삭제"
            ]
        })
    },
    "IPsec VTI 명령어 (Virtual Tunnel Interface)": {
        "[Phase1] ISAKMP SA 생성": pd.DataFrame({
            "명령어": [
                "crypto isakmp policy 10",
                "encryption aes",
                "authentication pre-share",
                "hash md5",
                "group 2",
                "crypto isakmp key cisco address 0.0.0.0 0.0.0.0"
            ],
            "설명": [
                "IKE 정책을 설정 (정책 번호 10)",
                "AES 암호화 알고리즘을 사용",
                "사전 공유 키 방식의 인증을 설정",
                "MD5 해시 알고리즘을 사용",
                "Diffie-Hellman 그룹 번호를 설정",
                "동적 IP를 가진 라우터와 VPN 터널을 설정하기 위한 사전 공유 키를 지정. (고정 IP를 가졌다면 그 IP를 지정)"
            ]
        }),
        
        "[Phase2] IPsec SA 생성" : pd.DataFrame({
            "명령어": [
                "crypto ipsec transform-set PHASE2 esp-aes esp-sha-hmac"
            ],
            "설명": [
                "IPSec 변환 세트를 설정. 'PHASE2'는 사용자가 정의한 이름."
            ]
        }),
        
        "[Phase3] IPsec Profile 생성" : pd.DataFrame({
            "명령어": [
                "crypto ipsec profile VTI-PROFILE",
                "set transform-set PHASE2"
            ],
            "설명": [
                "IPSec 프로필을 설정. 'VTI-PROFILE'은 사용자가 정의한 프로필 이름.",
                "프로필에 IPSec 변환 세트를 설정. 'PHASE2'는 이전에 정의한 변환 세트의 이름."
            ]
        }),
        
        "[Phase4] VTI_Tunnel 생성 및 적용" : pd.DataFrame({
            "명령어": [
                "interface tunnel <Num>",
                "ip address <IP> <Netmask>",
                "tunnel source <sIP>",
                "tunnel destination <dIP>",
                "tunnel mode ipsec ipv4",
                "tunnel protection ipsec profile VTI-PROFILE",
                "OSPF Neighbor"
            ],
            "설명": [
                "터널 인터페이스를 설정",
                "터널 인터페이스에 IP 주소를 할당",
                "터널의 출발지 IP 주소를 설정",
                "터널의 목적지 IP 주소를 설정. (상대가 동적 IP를 가지고 있다면 생략)",
                "터널을 VTI로 동작하게 설정",
                "터널에 IPSec 프로필을 적용하여 보안을 활성화. 'VTI-PROFILE'은 이전에 정의한 IPSec 프로필의 이름",
                "OSPF 설정으로 경로 광고 및 학습"
            ]
        })
    },
    "ASA_IPsec_VPN 명령어": {
        "[Phase1] SAKMP SA 생성" : pd.DataFrame({
            "명령어": [
                "(config)# crypto ikev1 policy 10",
                "(config-ikev1-policy)# authentication pre-share",
                "(config-ikev1-policy)# encryption aes",
                "(config-ikev1-policy)# hash sha",
                "(config-ikev1-policy)# group 2",
                "(config-ikev1-policy)# lifetime 3600",
                "(config)# crypto ikev1 enable OUTSIDE",
                "(config)# crypto isakmp identity address",
                "(config)# tunnel-group 10.10.10.2 type ipsec-l2l",
                "(config)# tunnel-group 10.10.10.2 ipsec-attributes",
                "(config-tunnel-ipsec)# ikev1 pre-shared-key MY_SHARED_KEY"
            ],
            "설명": [
                "IKEv1 정책을 설정. '10'은 정책 번호.",
                "사전 공유 키 방식의 인증을 사용.",
                "AES 암호화 알고리즘을 사용.",
                "SHA 해시 알고리즘을 사용.",
                "Diffie-Hellman 그룹 번호를 설정.",
                "보안 연결의 수명을 3600초로 설정.",
                "IKEv1을 외부 (OUTSIDE) 인터페이스에 활성화.",
                "ISAKMP 신원 검사를 IP 주소로 설정.",
                "IPsec 사이트 간 터널 그룹을 설정. 여기서 '10.10.10.2'는 터널의 대상 peer IP 주소. L2끼리 맺는 설정.",
                "IPsec 터널 그룹의 속성을 설정.",
                "IKEv1 사전 공유 키를 설정. 'MY_SHARED_KEY'는 공유 키의 실제 값."
            ]
        }),
        
        
        "[Phase2] IPsec SA 생성" : pd.DataFrame({
            "명령어": [
                "crypto ipsec ikev1 transform-set MY_TRANSFORM_SET esp-aes-256 esp-sha-hmac",
                "access-list LAN1_LAN2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0"
            ],
            "설명": [
                "IPSec IKEv1 변환 세트를 설정. 데이터를 AES-256 알고리즘으로 암호화하고, SHA 해시를 사용하여 데이터 무결성을 보장.",
                "ACL을 설정하여 LAN1 네트워크에서 LAN2 네트워크로의 모든 IP 트래픽을 허용."
            ]
        }),
        
        "[Phase3] Crypto MAP 생성 및 적용" : pd.DataFrame({
            "명령어": [
                "crypto map MY_CRYPTO_MAP 10 match address LAN1_LAN2",
                "crypto map MY_CRYPTO_MAP 10 set peer 10.10.10.2",
                "crypto map MY_CRYPTO_MAP 10 set ikev1 transform-set MY_TRANSFORM_SET",
                "crypto map MY_CRYPTO_MAP 10 set security-association lifetime seconds 3600",
                "crypto map MY_CRYPTO_MAP interface OUTSIDE"
            ],
            "설명": [
                "ACL 'LAN1_LAN2'와 일치하는 트래픽만 해당 IPSec 보안 정책에 매치.",
                "터널의 대상 피어 IP 주소를 설정. 여기서 '10.10.10.2'는 터널의 대상 IP 주소.",
                "IKEv1 변환 세트를 'MY_TRANSFORM_SET'으로 설정.",
                "보안 연결 수명을 3600초로 설정.",
                "'OUTSIDE' 인터페이스에 'MY_CRYPTO_MAP' IPSec 맵을 적용하여 외부와의 통신에 보안을 적용."
            ]
        })
    }
}






#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


#VRF


VRF = {
    "명령어": [
        "config)# ip vrf [vrf_name]",
        "config)#interface FastEthernet 0/0",
        "config-if)#ip vrf forwarding <Blue>",
        "config-if)#ip address <192.168.1.254> <255.255.255.0>",
        "ip route vrf <VRF Name> <IP> <NetMask>",
        "",
        "show ip route vrf <VRF Name>",
        "show ip vrf",
        "ping vrf <Blue> <192.168.1.1>"
    ],
    "설명": [
        "VRF 이름 지정 (대소문자 구분)",
        "VRF를 적용할 인터페이스에 접근",
        "이 인터페이스에 VRF를 <Blue>로 실행",
        "인터페이스 IP 지정",
        "VRF에 스태틱 라우트 설정",
        "",
        "가상 라우팅 테이블 확인 (show ip route로는 VRF를 볼 수 없음)",
        "VRF 인터페이스 확인",
        "VRF의 인터페이스로 통신 확인"
    ]
}

VRF_OSPF = {
    "명령어": [
        "ISP(config)#router ospf 1 vrf Blue",
        "ISP(config-router)#network 192.168.1.0 0.0.0.255 area 0",
        "ISP(config-router)#network 192.168.3.0 0.0.0.255 area 0",
        "",
        "show ip route vrf <VRF Name> ospf",
        "",
        "여러 VRF로 OSPF를 구성할 시"
    ],
    "설명": [
        "<Blue1>과 <Blue2> 사이에 존재하는 중앙 집결지의 <ISP>가 VRF로 OSPF 설정을 해줘야 함",
        "<ISP>가 <Blue1>의 네트워크와 Neighbor",
        "<ISP>가 <Blue2>의 네트워크와 Neighbor",
        "",
        "<이름>의 OSPF 테이블 확인.",
        "",
        "OSPF의 ID를 다르게 설정해야 함"
    ]
}

VRF_BGP = {
    "명령어": [
        "config)#ip vrf <Name>",
        "config-vrf)#rd [ASN:nn]",
        "config)#interface FastEthernet 0/0",
        "config-if)# ip vrf forwarding [vrf_name]",
        "config-if)#ip address <192.168.1.254> <255.255.255.0>",
        "config)#router bgp [ASNum]",
        "config-router)# address-family ipv4 vrf [vrf_name]",
        "",
        "show ip route vrf blue bgp",
        "show bgp vpnv4 unicast all summary",
        "show ip bgp vpnv4 vrf <VRF ID>",
        "",
        "제3의 라우터와 테이블 공유 시"
    ],
    "설명": [
        "VRF 생성",
        "BGP 연동 시 VRF를 구분하기 위한 값 지정",
        "VRF를 적용할 인터페이스에 접근",
        "특정 인터페이스에 VRF를 할당. 할당할 시 이 인터페이스의 설정은 다 초기화 됨. (VLAN 인터페이스 지정과 같은 원리)",
        "인터페이스 IP 지정",
        "BGP Num을 지정하여 BGP 생성",
        "<이름>을 가진 VRF로 BGP를 실행",
        "",
        "VRF <이름>의 BGP 테이블 확인",
        "BGP Neighbor 확인",
        "VRF를 구분하는 VRF RD 값 확인",
        "",
        "제 3의 라우터도 같은 rd 값을 가진 라우팅 테이블을 구성해야 공유 가능"
    ]
}


VRF_tables = {"VRF 설정 명령어 (집결지 라우터만 설정)":VRF,
              "OSPF 연동 명령어 (집결지 라우터만 설정)": VRF_OSPF,
              "BGP 연동 명령어 (집결지 라우터만 설정)": VRF_BGP
           }
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#Nexus


host_name_interface_command = {
    "명령어": [
        "config)# switchname N9K-1",
        "config)# interface mgmt0",
        "config-if)# ip address 10.1.50.1 255.255.255.0"
    ],
    "설명": [
        "해당 장비의 호스트 이름을 'N9K-1'로 설정",
        "관리 인터페이스(Mgmt0)로 이동. (Management VRF에 기본으로 소속)",
        "관리 인터페이스에 IP 주소를 할당"
    ]
}

stp_port_type = {
    "명령어": [
        "spanning-tree port type <type>"
    ],
    "설명": [
        "STP 포트 타입 설정"
    ]
}
vrf_command = {
    "명령어": [
        "config)# vrf context management",
        "config-vrf)# ip route 0.0.0.0/0 10.1.50.254",
        "config-if)# vrf member <VRF Name>",
        "(config-router)# vrf <VRF Name>"
    ],
    "설명": [
        "관리 VRF(Virtual Routing and Forwarding) 컨텍스트를 생성하거나 변경",
        "관리 VRF의 Default 라우팅 설정",
        "인터페이스를 지정된 VRF에 소속",
        "특정 Routing Protocol에 VRF 할당"
    ]
}

routing_network_command = {
    "명령어": [
        "config)# ntp server 172.20.11.2",
        "config)# copp profile strict",
        "",
        "show ip interface brief vrf management",
        "show vrf",
        "show ip route",
        "show ip route vrf management"
    ],
    "설명": [
        "NTP(Network Time Protocol) 서버 주소를 172.20.11.2로 설정",
        "Control Plane Policing(CoPP) 프로파일을 엄격 모드로 설정",
        "",
        "관리 VRF(Virtual Routing and Forwarding)에 속한 인터페이스의 간단한 IP 정보를 표시",
        "시스템에 구성된 VRF(Virtual Routing and Forwarding) 목록을 표시",
        "시스템의 IP 라우팅 테이블을 표시",
        "관리 VRF(Virtual Routing and Forwarding)에 대한 IP 라우팅 테이블을 표시"
    ]
}

security_authentication_command = {
    "명령어": [
        "config)# username admin password cisco123 role network-admin",
        "config)# no feature telnet",
        "config)# ssh key rsa 1024 force",
        "config)# feature ssh",
        "config)# password strength-check"
    ],
    "설명": [
        "사용자 이름이 'admin'이고 비밀번호가 'cisco123'이며 역할이 'network-admin'인 사용자를 추가",
        "Telnet 서비스를 비활성화",
        "RSA 암호화 알고리즘을 사용하여 1024비트의 SSH 키를 생성하고, 이미 존재하는 경우에도 덮어쓰기",
        "SSH 서비스를 활성화",
        "강화된 패스워드 설정"
    ]
}

boot_system_command = {
    "명령어": [
        "config)# boot nxos bootflash:nxos64-cs.10.2.4.M.bin",
        "cli alias name <Name> <config>",
        "",
        "dir"
    ],
    "설명": [
        "지정된 Nexus 운영 체제(NX-OS) 이미지 파일을 부트플래시로 설정하여 장비를 해당 버전으로 부팅",
        "약어를 사용하여 Config 설정",
        "",
        "파일 경로 확인"
    ]
}

role_command = {
    "명령어": [
        "config)# role name OSPF_Config",
        "config-role)# rule 1 permit command config t ; interface *",
        "config-role)# rule 2 permit read-write feature router-ospf",
        "config-role)# rule 3 permit read feature router-bgp",
        "config)# username admin2 password cisco role OSPF_Config",
        "",
        "show user-account",
        "show role",
        "show role feature-group",
        "show role feature"
    ],
    "설명": [
        "\"OSPF_Config\"라는 이름의 역할을 생성",
        "역할에 대한 규칙 1을 설정. \"config t\" 명령어와 \"interface *\" 명령어에 대한 사용을 허용",
        "역할에 대한 규칙 2를 설정. \"router-ospf\" 기능에 대한 읽기/쓰기 액세스를 허용",
        "역할에 대한 규칙 3을 설정. \"router-bgp\" 기능에 대한 읽기 액세스를 허용",
        "사용자 이름이 \"admin1\"이고 비밀번호가 \"cisco\"인 사용자를 추가하며, 해당 사용자에게 \"OSPF_Config\" 역할을 할당",
        "",
        "사용자 계정 정보를 표시",
        "시스템에 구성된 역할 정보를 표시",
        "역할 그룹에 속한 기능 정보를 표시",
        "역할이 사용할 수 있는 기능 정보를 표시"
    ]
}

feature_command = {
    "명령어": [
        "feature <Feature Name>",
        "",
        "show feature",
        "show run | sec feature"
    ],
    "설명": [
        "OSPF와 같은 Feature를 활성화",
        "",
        "Feature 활성화 상태를 확인",
        "run config에서 feature 설정을 확인"
    ]
}

rollback_command = {
    "명령어": [
        "checkpoint <C Name>",
        "rollback run checkpoint <C name>",
        "checkpoint file <dir>",
        "rollback run file <dir: C Name>",
        "",
        "show checkpoint <C Name>",
        "show checkpoint summary",
        "dir"
    ],
    "설명": [
        "User Checkpoint를 <C Name>으로 임시 저장",
        "User Checkpoint를 롤백하여 실행",
        "체크포인트를 <dir>에 파일로 저장",
        "User Checkpoint 파일을 <dir: C Name>으로 롤백하여 실행",
        "",
        "<C Name>의 체크포인트 확인",
        "체크포인트 축약 정보 확인",
        "디렉토리(저장소) 확인 (파일 형태의 체크포인트 확인용)"
    ]
}

ospf_commands = {
    "명령어": [
        "feature ospf",
        "router ospf 1",
        "router-id <IP형식의 ID>",
        "interface <Interface>",
        "ip router ospf 1 area <Area Num>",
        "ip ospf passive-interface"
    ],
    "설명": [
        "OSPF 활성화",
        "OSPF 생성",
        "OSPF router ID 생성",
        "OSPF 적용을 할 인터페이스에 접속",
        "이 인터페이스가 어떤 OSPF Area에 속할지 설정",
        "Hello 메세지를 보내지 않겠다는 설정"
    ]
}

bgp_commands = {
    "명령어": [
        "feature bgp",
        "router bgp <AS Num>",
        "neighbor <IP> remote-as <AS Num>",
        "address-family ipv4 unicast",
        "network <IP/CIDR>",
        "next-hop-self"
    ],
    "설명": [
        "BGP 활성화",
        "BGP 생성",
        "Neighbor를 맺을 상대방의 IP와 AS Num 지정",
        "IPv4버전의 주소를 광고하기 위해 add-Family에 접속 (IPv4의 주소로 Neighbor를 활성화 하겠다는 뜻도 됨)",
        "광고할 네트워크 대역 지정",
        "Next Hop을 나의 주소로 변경하도록 설정"
    ]
}

vrf_commands = {
    "명령어": [
        "vrf context <VRF Name>",
        "ip route <IP/CIDR> <Next Hop IP>",
        "vrf member <VRF Name>",
        "vrf <VRF Name>"
    ],
    "설명": [
        "VRF 생성",
        "VRF에 Static route 설정",
        "특정 인터페이스에 VRF를 할당 (할당 즉시 기존의 L3 정보 삭제)",
        "특정 Routing Protocol에 VRF 할당"
    ]
}



nexus_tables = {"호스트 이름 및 인터페이스 설정 명령어":host_name_interface_command,
              "보안 및 인증 설정 명령어": security_authentication_command,
              "Feature 활성화 명령어": feature_command,
                "STP 포트 타입 설정": stp_port_type,
              "VRF 설정 명령어": vrf_command,
              "라우팅 및 네트워크 설정 명령어": routing_network_command,
              "부팅 및 파일 시스템 설정 명령어": boot_system_command,
              "사용자 역할 설정 명령어": role_command,
              "CheckPoint & Rollback 명령어": rollback_command,
                "OSPF 명령어" : ospf_commands,
                "BGP 명령어" : bgp_commands,
           }


#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#vPC

vpc = {
    "명령어": [
        "(config)# feature vpc",
        "(config)# vpc domain <Num>",
        "(config-vpc-domain)# role priority <Num[Default = 32667]>",
        "",
        "show vpc role"
    ],
    "설명": [
        "vPC 기능 활성화",
        "vPC 도메인 생성",
        "장비의 우선순위 값 설정",
        "",
        "vPC 역할 확인"
    ]
}

keep_alive_link = {
    "명령어": [
        "(config)# feature vpc",
        "",
        "(config)# vrf context <VRF Name>",
        "",
        "(config)# interface <KAL Interface>",
        "(config-if)# vrf member <VRF Name>",
        "(config-if)# ip address <내 IP/sub>",
        "",
        "(config)# vpc domain <Num>",
        "(config-vpc-domain)# peer-keepalive destination <상대 IP> source <내 IP> vrf <VRF Name>",
        "",
        "show vpc peer-keepalive"
    ],
    "설명": [
        "vPC(Virtual Port Channel) 기능 활성화",
        "",
        "KeepAlive Link를 위한 VRF 생성",
        "",
        "KeepAlive 인터페이스에 접속",
        "이 포트가 참고할 VRF를 지정",
        "이 포트의 IP 주소 설정",
        "",
        "vPC 도메인 생성 또는 접속",
        "KeepAlive 메시지를 보낼 때 사용할 도착지 IP, 출발지 IP, VRF 설정",
        "",
        "peer-keepalive 상태 확인"
    ]
}

peer_link = {
    "명령어": [
        "(config)# feature lacp",
        "(config)# feature vpc",
        "",
        "(config)# interface <ethernet 3/1, ethernet 4/1>",
        "(config-if)# channel-group <2> mode active",
        "",
        "(config)# interface port-channel <2>",
        "(config-if)# switchport mode trunk",
        "(config-if)# switchport trunk allowed vlan <1-100>",
        "(config-if)# spanning-tree port type network",
        "(config-if)# vpc peer-link",
        "",
        "(config)# interface <Interface>",
        "(config-if)# switchport mode trunk",
        "(config-if)# switchport trunk allowed vlan <100-200>"
    ],
    "설명": [
        "LACP 기능 활성화",
        "vPC 기능 활성화",
        "",
        "설정을 시작할 Ethernet 인터페이스에 접속 (모듈 이원화)",
        "포트 채널 그룹 2를 활성 LACP 모드로 설정",
        "",
        "포트 채널 그룹 2에 접속하여 설정을 시작",
        "포트 채널을 트렁크 모드로 설정(VLAN 통신을 할 때도 있기 때문)",
        "트렁크에 허용되는 VLAN 설정 (VLAN 1부터 100까지 허용)",
        "포트를 네트워크 유형으로 설정 (Default 적용으로서 생략 가능)",
        "vPC 피어 링크 설정",
        "",
        "Orphan 구성 시 None Member(vPC) VLAN 인터링크로 사용할 인터페이스 지정.",
        "트렁크 모드로 설정.",
        "None Member VLAN 통신할 VLAN 설정."
    ]
}

member_port = {
    "명령어": [
        "(config)# interface ethernet 2/3",
        "(config-if)# channel-group <Num> mode active",
        "",
        "(config)# interface port-channel <Num>",
        "(config-if)# switchport mode trunk",
        "(config-if)# switchport trunk allowed <vlan 1-100>",
        "(config-if)# spanning-tree port guard root",
        "(config-if)# vpc 10",
        "",
        "show vpc",
        "show vpc orphan-ports"
    ],
    "설명": [
        "vPC 멤버 포트에 접속하여 설정을 시작",
        "LACP 모드로 설정",
        "",
        "포트 채널 그룹에 접속하여 설정을 시작",
        "포트 채널을 트렁크 모드로 설정",
        "Member VLAN 설정 (VLAN 1부터 100까지 허용)",
        "포트를 루트 가드로 설정",
        "포트 채널에 vPC 활성화",
        "Peer 장비에도 똑같은 Config 입력",
        "vpc 상태 확인",
        "Orphan Port 확인"
    ]
}



vpc_error_commands = {
    "명령어": [
        "(config-vpc-domain)# auto recovery",
        "(config-vpc-domain)# auto recovery reload-delay",
        "",
        "(config-vpc-domain)# vpc role preempt",
        "",
        "(config-vpc-domain)# peer-switch",
        "(config-vpc-domain)# peer-gateway",
        "(config-vpc-domain)# ip arp synchronize",
        "",
        "(config-vpc-domain)# dual-active exclude interface-vlan <VLAN Num>",
        "(config-if)# vpc orphan-ports suspend"
    ],
    "설명": [
        "Peer Link가 끊어진 후 S장비가 Member Port를 차단한 뒤 P장비가 Down되는 상황에서 장애를 대비하기 위한 명령어. Secondary 장비에서 걸어주는 명령어로 장비가 KeepAlive 메세지를 연속 3회 동안 받지 못하면 자신의 Suspend 포트를 풀고 Operational Primary로 동작하게 됨.",
        "Peer 장비들을 동시에 Reboot하였지만 한 대의 장비가 booting되지 않아 서로 vPC 협상을 맺지 않고 vPC 활성화가 되지 않을 때 지정하는 명령어. 협상이 일정 시간 이상 진행되지 않는 경우 해당 장비를 Primary로 실행 함.",
        "",
        "vPC Role을 중요도 순으로 역할을 재정리하는 명령어.",
        "",
        "STP/BPDU는 P장비가 주도함. P장비가 Down될 경우 S장비가 STP를 주도하기 위해 주도권을 가져오는데 이때 DownTime이 3초 발생. 이를 방지하기 위해 System MAC을 Bridge ID로 사용하여 두 장비 모두에게 STP 주도권을 주어 DownTime을 없애는 명령어. (두 장비의 STP Priority를 같게 설정해야 함 `spanning-tree vlan <Member VLAN Num> priority <priority>`)",
        "이중화 구성 시 출발 패킷은 가상 MAC 주소를 보고 게이트웨이로 향한 뒤 SVI 인터페이스의 MAC을 src로 달고 내려감. 되돌아 오는 패킷도 마찬가지로 가상 MAC을 향해 보내지며 내려올 때 SVI 인터페이스의 MAC을 달고 내려감. 그러나 패킷을 반송하는 장비가 가상 MAC이 아닌 실제 MAC을 향해 패킷을 보낸다면 패킷 손실이 발생할 수 있음. 예로 만약 P장비의 실제 MAC을 dest로 넣고 패킷을 쏜 뒤 이 패킷이 S장비로 향하게 되면 S장비는 P장비의 MAC정보를 알기 때문에 Peer링크로 이 패킷을 P장비에 전달. 하지만 이는 로컬 처리 룰에 어긋나기 때문에 패킷을 전달하지 않음. 이를 방지하기 위해 P와 S장비가 서로의 실제 MAC 주소를 공유하여 본인이 직접 이 패킷을 로컬 처리 하기 위해 설정하는 명령어. (두 장비는 자신과 상대의 실제 MAC 주소를 G Flag를 달고 테이블에 올림. 실제 Gateway MAC 주소를 공유하여 로컬로 처리할 수 있게 만드는 것)",
        "Peer Link 가 Down되면 Peer 장비들은 상대방의 ARP 정보를 손실하게 됨. Peer Link가 다시 연결됐을 때 ARP 테이블을 채우려면 시간이 걸리게 됨. 이를 방지하기 위해 서로의 ARP 테이블을 공유하여 동일하게 저장하는 명령어.",
        "",
        "Peer Link 다운 시 Orphan Port를 살리는 방법(별도의 인터링크가 필요함). vPC 도메인에 `dual-active exclude interface-vlan <VLAN Num>` 명령어를 입력하여 Peer Link가 Down되도 VLAN은 UP 상태로 유지.",
        "Peer Link 다운 시 Orphan Port를 죽이는 방법. Orphan Port 인터페이스에 `vpc orphan-ports suspend` 명령어를 입력하여 Peer Link가 다운될 시 Orphan Port도 함께 Down시킴.(이 명령어를 Orphan Port가 아닌 인터페이스에 적용해도 위 상황 시 Down이 되기 때문에 주의해야 함)"
    ]
}


# 단어와 설명을 딕셔너리로 정의
definitions = {
    "vPC Domain": "vPC의 환경 자체를 말하는 것으로 세부 환경 설정을 해야 하며 Nexus 장비는 단 하나의 vPC Domain와 단 두 대의 Peer장비 만을 가질 수 있음.",
    "vPC": "가상의 Port-Channel. 포트들을 특정 Number값을 가진 vPC로 선언하면 지정된 포트들은 가상의 하나로 묶여진 포트로 동작 함.(하단의 장비가 이렇게 인식하는 것. vPC장비는 선언만 해줌.)",
    "Peer Device": "vPC 도메인 내의 두 장비를 말함.",
    "Member Port": "vPC 선언이 된 인터페이스.",
    "Member VLAN": "vPC에 Allowed된 VLAN.",
    "Orphan Port": "vPC 장비에 VLAN이 Allowed 되었지만 vPC 선언은 되지 않은 포트.",
    "KeepAlive Link": "Peer 장비 간에 상태 정보를 주고 받는 역할을 하지만 vPC 협상이 이루어진 후, Peer Link도 서로의 상태 정보를 CFS로 주고 받기 때문에 KeepAlive 정보 이중화라고 보면 됨.",
    "Peer Link": "Peer 장비 간에 상태 정보를 주고 받으며 Primary의 MAC address, IGMP snooping, Config consistency check, vPC Member Port status, BPDU 정보를 모두 동기화하는 링크."
}




vpc_tables = {"vPC 도메인 생성 및 우선 값 명령어": vpc,
              "KeepAlive Link 설정 명령어":keep_alive_link,
              "Peer Link 설정 명령어": peer_link,
              "Member Port선언 및 Port Channel 구성 명령어": member_port,
              "vPC 장애 대비 명령어" : vpc_error_commands
           }
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


ospf_pim_commands = {
    "명령어": [
        "feature ospf",
        "feature pim",
        "router ospf 1",
        "router-id 10.1.1.1",
        "int eth1/1",
        "description TO_N9K-3_ETH1/1",
        "no switchport",
        "mtu 9216",
        "ip address 1.1.13.1/30",
        "ip router ospf 1 area 0",
        "ip ospf network point-to-point",
        "ip pim sparse-mode",
        "no shut",
        "int lo0",
        "ip address 10.1.1.1/32",
        "ip router ospf 1 area 0",
        "ip pim sparse-mode"
    ],
    "설명": [
        "OSPF 프로토콜을 활성화함",
        "PIM (Protocol Independent Multicast)을 활성화함",
        "OSPF 프로세스를 설정하고 ID를 할당함",
        "OSPF 라우터 ID 설정",
        "이더넷 인터페이스 설정",
        "인터페이스 설명 설정",
        "스위치 모드를 비활성화함",
        "최대 전송 단위(MTU) 설정 (Jumbo Frame)",
        "인터페이스 IP 주소 및 서브넷 마스크 설정",
        "OSPF 광고 및 Neighbor 설정",
        "OSPF 네트워크 유형을 Point-to-Point로 설정",
        "PIM의 희소 모드를 설정함",
        "인터페이스를 활성화함",
        "루프백 인터페이스 설정",
        "루프백 인터페이스 IP 주소 설정",
        "OSPF 영역 설정",
        "PIM의 희소 모드를 설정함"
    ]
}

ospf_pim_nv_commands = {
    "명령어": [
        "feature ospf",
        "feature pim",
        "feature nv overlay",
        "feature vn-segment-vlan-based",
        "feature interface-vlan",
        "router ospf 1",
        "router-id 10.1.1.3",
        "int eth1/1",
        "description TO_N9K-1_ETH1/1",
        "no switchport",
        "mtu 9216",
        "ip address 1.1.13.2/30",
        "ip router ospf 1 area 0",
        "ip ospf network point-to-point",
        "ip pim sparse-mode",
        "no shut",
        "int lo0",
        "ip address 10.1.1.3/32",
        "ip router ospf 1 area 0",
        "ip pim sparse-mode"
    ],
    "설명": [
        "OSPF 프로토콜을 활성화함",
        "PIM (Protocol Independent Multicast)을 활성화함",
        "VTEP/NVE 기능 활성화",
        "VxLAN 번호 헤더를 붙이는 기능 활성화",
        "SVI 활성화",
        "OSPF 프로세스를 설정하고 ID를 할당함",
        "OSPF 라우터의 고유 식별자를 설정함",
        "이더넷 인터페이스 설정",
        "인터페이스 설명 설정",
        "스위치 모드를 비활성화함",
        "최대 전송 단위(MTU) 설정",
        "인터페이스 IP 주소 및 서브넷 마스크 설정",
        "OSPF 영역 설정",
        "OSPF 네트워크 유형을 Point-to-Point로 설정",
        "PIM의 희소 모드를 설정함",
        "인터페이스를 활성화함",
        "루프백 인터페이스 설정",
        "NVE 인터페이스 IP 주소 설정",
        "OSPF 영역 설정",
        "PIM의 희소 모드를 설정함"
    ]
}


pim_anycast_rp_commands = {
    "명령어": [
        "ip pim rp-address 10.1.1.10 group-list 225.0.0.0/24",
        "ip pim anycast-rp 10.1.1.10 10.1.1.1",
        "ip pim anycast-rp 10.1.1.10 10.1.1.2",
        "int lo1",
        "description Anycast RP",
        "ip address 10.1.1.10/32",
        "ip router ospf 1 area 0",
        "ip ospf network point-to-point",
        "ip pim sparse-mode",
        "",
        "ip pim rp-address 10.1.1.10"
    ],
    "설명": [
        "10.1.1.10의 주소를 가진 RP에게 225.0.0.0/24 Mcast를 처리하도록 설정",
        "Anycast RP를 설정하고 그룹 주소에 대한 RP 주소를 할당함",
        "Anycast RP를 설정하고 그룹 주소에 대한 RP 주소를 할당함",
        "루프백 인터페이스 설정",
        "인터페이스 설명 설정",
        "인터페이스 IP 주소 설정",
        "OSPF 영역 설정",
        "OSPF 네트워크 유형을 Point-to-Point로 설정",
        "PIM의 희소 모드를 설정함",
        "",
        "Leaf 장비에 PIM RP 주소를 설정함"
    ]
}

bgp_evpn_commands = {
    "명령어": [
        "feature bgp",
        "feature nv overlay",
        "nv overlay evpn",
        "router bgp 65535",
        "router-id 11.11.11.11",
        "neighbor 1.1.1.1",
        "remote-as 65535",
        "update-source loopback0",
        "address-family l2vpn evpn",
        "send-community both",
        "route-reflector-client"
    ],
    "설명": [
        "BGP(Border Gateway Protocol)를 활성화합니다.",
        "Network Virtualization(NV) 오버레이 기능을 활성화합니다.",
        "MAC/IP 주소를 포함한 L2VPN/EVPN을 BGP로 전달하도록 하는 명령어.",
        "BGP 프로토콜을 사용하여 BGP 프로세스를 시작, 자체 AS(Autonomous System) 번호를 65535로 설정.",
        "BGP 라우터 식별자를 11.11.11.11로 설정.",
        "이웃 BGP 라우터의 주소를 1.1.1.1로 설정.",
        "이웃 BGP 라우터의 AS 번호 65535.",
        "BGP 네트워크에 대한 업데이트를 보낼 소스 인터페이스를 loopback0으로 설정.",
        "EVPN을 사용하는 Layer 2 VPN(L2VPN) 주소 패밀리를 활성화.",
        "BGP 업데이트에서 양방향 커뮤니티를 보냄.",
        "이 BGP 라우터를 라우트 리플렉터 클라이언트로 설정하여 다른 라우터로부터 라우팅 업데이트를 받음."
    ]
}

nv_overlay_commands = {
    "명령어": [
        "interface nve1",
        "no shutdown",
        "source-interface loopback0",
        "host-reachability protocol bgp",
        "feature vn-segment-vlan-based",
        "vlan 11",
        "name Customer-A_Network-11",
        "vn-segment 10011",
        "vlan 123",
        "name Customer-A_L3VNI",
        "vn-segment 111213",
        "vrf context Customer-A",
        "vni 111213"
    ],
    "설명": [
        "VxLAN의 작업대인 NVE를 생성하고 설정창에 접속.",
        "지정한 인터페이스를 활성화.",
        "NVE의 소스 인터페이스를 loopback0으로 설정.",
        "BGP 프로토콜을 사용하여 호스트 접근성을 설정.",
        "VLAN을 기반으로 하는 가상 네트워크(VN) 세그먼트 기능을 활성화.",
        "VLAN 11을 생성.",
        "VLAN 11의 이름을 'Customer-A_Network-11'로 지정.",
        "VLAN 11의 VN 세그먼트 ID를 10011로 설정.",
        "VLAN 123을 생성.",
        "VLAN 123의 이름을 'Customer-A_L3VNI'로 지정.",
        "VLAN 123의 VN 세그먼트 ID를 111213로 설정.",
        "Customer-A라는 VRF(Virtual Routing and Forwarding) 컨텍스트를 생성.",
        "VRF Customer-A에서 VNI(Virtual Network Identifier) 111213을 설정."
    ]
}

nv_overlay_commands2 = {
    "명령어": [
        "interface nve1",
        "no shutdown",
        "source-interface loopback0",
        "host-reachability protocol bgp",
        "feature vn-segment-vlan-based",
        "vlan 11",
        "name Customer-A_Network-11",
        "vn-segment 10011",
        "vlan 123",
        "name Customer-A_L3VNI",
        "vn-segment 111213",
        "vrf context Customer-A",
        "vni 111213",
        "feature interface-vlan",
        "fabric forwarding anycast-gateway-mac 1234.1234.1234",
        "interface vlan 11",
        "no shutdown",
        "vrf member Customer-A",
        "ip address 1.1.11.1/24",
        "fabric forwarding mode anycast-gateway",
        "interface vlan 123",
        "no shutdown",
        "ip forward"
    ],
    "설명": [
        "NV 오버레이 터널 인터페이스를 지정하고 해당 인터페이스를 설정.",
        "지정한 인터페이스를 활성화.",
        "NV 오버레이 터널의 소스 인터페이스를 loopback0으로 설정.",
        "BGP 프로토콜을 사용하여 호스트 접근성을 설정.",
        "VLAN을 기반으로 하는 가상 네트워크(VN) 세그먼트 기능을 활성화.",
        "VLAN 11을 생성.",
        "VLAN 11의 이름을 'Customer-A_Network-11'로 지정.",
        "VLAN 11의 VN 세그먼트 ID를 10011로 설정.",
        "VLAN 123을 생성.",
        "VLAN 123의 이름을 'Customer-A_L3VNI'로 지정.",
        "VLAN 123의 VN 세그먼트 ID를 111213로 설정.",
        "Customer-A라는 VRF(Virtual Routing and Forwarding) 컨텍스트를 생성.",
        "VRF Customer-A에서 VNI(Virtual Network Identifier) 111213을 설정.",
        "인터페이스 VLAN을 활성화.",
        "패브릭 포워딩에서 사용하는 애니캐스트 게이트웨이 MAC 주소를 설정.",
        "VLAN 11에 대한 인터페이스 설정.",
        "지정한 인터페이스를 활성화.",
        "인터페이스를 VRF(Customer-A)의 멤버로 지정.",
        "VLAN 11에 대한 IP 주소를 설정.",
        "패브릭 포워딩 모드를 애니캐스트 게이트웨이 모드로 설정.",
        "VLAN 123에 대한 인터페이스를 설정하고, VRF 멤버로서 Customer-A를 연결하며, IP 전달을 활성화.",
        "지정한 인터페이스를 활성화.",
        "인터페이스를 IP 전달 모드로 설정."
    ]
}

configuration_data = {
    "명령어": [
        "interface nve1",
        "member vni 10011",
        "mcast-group 239.0.0.11",
        "member vni 111213 associate-vrf",
        "router bgp 65535",
        "vrf Customer-A",
        "address-family ipv4 unicast",
        "redistribute direct route-map DIRECT",
        "route-map DIRECT permit 10"
    ],
    "설명": [
        "NV 오버레이 터널 인터페이스를 설정하고, VNI 10011을 구성하며, 멀티캐스트 그룹을 239.0.0.11로 설정하고, VRF와 연결된 VNI 111213을 연결.",
        "인터페이스에 VNI 10011을 매핑.",
        "멀티캐스트 그룹 주소를 설정.",
        "인터페이스에 VNI 111213을 VRF와 연결.",
        "BGP 프로세스를 시작.",
        "VRF Customer-A에 대한 BGP 라우터 구성을 시작.",
        "IPv4 유니캐스트 주소 패밀리를 활성화. (IPv4로 통신)",
        "직접 연결된 디바이스를 다시 분배(광고)하고, route-map을 사용하여 특정 조건을 적용.",
        "모든(10) 디바이스를 분배(광고)함."
    ]
}

VxLAN_Show_commands = {
    "명령어": [
        "show nve peers",
        "show nve vni",
        "show ip arp suppression-cache detail",
        "show vxlan interface",
        "show bgp l2vpn evpn summary",
        "show bgp l2vpn evpn",
        "show l2route evpn mac all",
        "show l2route evpn mac-ip all",
        "PC# arp -n"
    ],
    "설명": [
        "NV 터널 엔진(NVE) 피어에 대한 정보를 표시.",
        "VNI번호/상태/모드/타입 등을 확인.",
        "IP ARP 억제 캐시에 대한 자세한 정보를 표시.",
        "VXLAN 인터페이스 정보 표시. (Nexus 9300에서는 지원되지 않음)",
        "EVPN 요약 정보 주소 확인.",
        "EVPN 주소 확인.",
        "EVPN 맥 주소에 대한 모든 L2 라우팅 정보를 표시.",
        "EVPN 맥-IP 주소에 대한 모든 L2 라우팅 정보를 표시합니다.",
        "PC에서 ARP 테이블 확인."
    ]
}













VXLAN_table = {"Underlay Spine OSPF설정 명령어": ospf_pim_commands,
              "Underlay Spine MP BGP EVPN 설정 명령어": bgp_evpn_commands,
              "Underlay Leaf 설정 명령어":ospf_pim_nv_commands,
              "Multicast 환경을 위한 RP(랑데뷰 포인트) 설정 명령어": pim_anycast_rp_commands,
              "NVE & VLAN 설정 명령어": nv_overlay_commands,
              "L2/L3 VxLAN 인터페이스 설정 명령어 ": nv_overlay_commands2,
              "NVE에 VLAN을 Member로 넣고 BGP로 광고하는 설정 명령어 ": configuration_data,
              "VxLAN 상태 확인 명령어 ": VxLAN_Show_commands,
           }
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# 커스텀 워닝 문구
def custom_warning(message):
    st.markdown(f'<div style="color: orange; font-size: large;">{message}</div>', unsafe_allow_html=True)



# 이미지를 URL로 추가하는 코드
image_url = "https://github.com/pDuKyu/switch/blob/main/20210112_163404.jpg?raw=true"
use_container_width = True
caption=''
st.sidebar.image(image_url, caption=caption, use_container_width=use_container_width)


# 한글 요일 매핑
weekdays_kr = {
    '1': '월요일',
    '2': '화요일',
    '3': '수요일',
    '4': '목요일',
    '5': '금요일',
    '6': '토요일',
    '0': '일요일'
}

# 오늘 날짜와 요일 가져오기
today_date = datetime.today().strftime('%Y-%m-%d')
weekday_num = datetime.today().strftime('%w')  # 숫자로 된 요일

# 한글로 변환된 요일을 가져오기
weekday_kr = weekdays_kr[weekday_num]

# 결과 출력
st.sidebar.write(f"오늘은 {today_date} {weekday_kr} 입니다!")



# 사이드바에 버튼 추가
page = st.sidebar.selectbox("명령어를 확인할 기기를 선택해주세요.", ["Switch", "Router", "FireWall", "VPN", "VRF", "Nexus", "Nexus vPC", "Nexus VxLAN"])



# 스위치 페이지
if page == "Switch":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('스위치 설정 명령어')

    # 선택한 테이블의 데이터 표시
    table_names = list(tables.keys())
    selected_table = st.selectbox("", table_names)  

    
    selected_df = tables[selected_table]
    st.dataframe(selected_df, width=800)


    st.success(text)
    st.write('')
    st.write('')
    st.write('')
    st.write('')
    st.write('')
    st.markdown("**알아야 할 Switch 용어**")
    st.markdown("이더넷 헤더  |  [ARP프로토콜](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#5adbab7beab0475fa1312af106c4b027)  |  [LAN](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#e90619ac89694afbbc76d2afb58b4c9e)  |  [VLAN](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#66916382c2cf4fd19cf6adba72d58959)  |  [트렁크](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#526de6ef5bb84ff19d52a84b566874b5)  |  [VTP](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#fce97913a59848acb4a5278b5e5b3087)  |  [Native VLAN](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#86d55c1d27ee474ca347af8256c86884)  |  [Allowed VLAN](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#9373ea0a750841a79ca58ef0ca04a3aa)  |  [Spanning-Tree](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#a68460c49db24bd4b1f7d3a4366e08fc)  |  [BPDU](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#1f379c70abb74050a09b73db36a6c637)  |  [PVST](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#3c834b70666d412d9f923729c9f76a80)  |  [RPVST](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#1266000c9e5e4ddf8a5131b1f07b586c)  |  [Etherchannel](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#907033e4a07f4a6a9a9c9362348b68ee)  |  [SVI](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#d2d0e2925f044cc4ba888e64409c5fcc)  |  [Routedport](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#db1a0bd441024c4e8b9464677a82827e)  |  [HSRP](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#8ecacfb272d547a4b91495a791142b0f)  |  [VRRP](https://www.notion.so/543021e334a04929a75f00db36ec89f9?pvs=4#9307d07092d548b0a933428db3afcc09)")


#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# 라우터 페이지
elif page == "Router":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('라우터 설정 명령어')


#리스트 기능
    table_names2 = list(r_tables.keys())
    selected_table2 = st.selectbox("", table_names2)  

#테이블 시각화
    selected_df2 = r_tables[selected_table2]
    st.dataframe(selected_df2, width=800)
    text2 = """
    **라우터**는 네트워크 간의 데이터를 안전하고 효율적으로 전달하는 역할을 하며, 이를 위해 
    
    네트워크 간의 경로를 결정하여 데이터를 전송하고, 패킷 단위로 데이터를 분할하여 
    
    목적지까지 안전하게 전송합니다. 


    
    또한, **라우터**는 서로 다른 네트워크 간의 통신을 관리하여 네트워크 간의 충돌을 방지하고 보안을 강화합니다. 
    
    이러한 기능을 통해 **라우터**는 신뢰성 높은 네트워크 통신을 가능하게 합니다.
    """
    st.success(text2)


#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 방화벽 페이지

elif page == "FireWall":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('방화벽 설정 명령어')

#리스트 기능
    table_names3 = list(F_tables.keys())
    selected_table3 = st.selectbox("", table_names3)  

#테이블 시각화
    selected_df3 = F_tables[selected_table3]
    st.dataframe(selected_df3, width=800)

#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


# VPN 페이지

elif page == "VPN":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('VPN 설정 명령어')


    # dict1의 명령어 선택
    selected_command12 = st.selectbox("명령어 선택", VPN_LIST)
    
    # 선택된 명령어에 따라 dict2의 세부 내용 표시
    if selected_command12:
        selected_details = st.selectbox(f"{selected_command12} Phase", list(network_commands[selected_command12].keys()))
    
        # 선택된 세부 내용에 따라 출력
        if selected_details:
            if isinstance(network_commands[selected_command12][selected_details], list):
                st.write("내용:")
                option_df = pd.DataFrame({"옵션": network_commands[selected_command12][selected_details]})
                st.write(option_df)
            else:
                st.write(network_commands[selected_command12][selected_details])



#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# VRF 페이지

elif page == "VRF":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('VRF 설정 명령어')

#리스트 기능.
    table_names5 = list(VRF_tables.keys())
    selected_table5 = st.selectbox("", table_names5)  

#테이블 시각화
    selected_df5 = VRF_tables[selected_table5]
    st.dataframe(selected_df5, width=800)


#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Nexus 페이지




elif page == "Nexus":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('Nexus 장비 설정 명령어')

#리스트 기능.
    table_names6 = list(nexus_tables.keys())
    selected_table6 = st.selectbox("", table_names6)

#테이블 시각화
    selected_df6 = nexus_tables[selected_table6]
    st.dataframe(selected_df6, width=800)




#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

elif page == "Nexus vPC":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('Nexus vPC 설정 명령어')

#리스트 기능.
    table_names7 = list(vpc_tables.keys())
    selected_table7 = st.selectbox("", table_names7)  

#테이블 시각화
    selected_df7 = vpc_tables[selected_table7]
    st.dataframe(selected_df7, width=800)

    st.write('')
    st.write('')
    st.write('')
    st.write('')
    st.write('')
    # 열 생성
    col1, col2, col3, col4 = st.columns(4)
    
    # 각 단어에 대한 버튼 생성
    for i, (word, definition) in enumerate(definitions.items()):
        if i % 4 == 0:
            button_container = col1
        elif i % 4 == 1:
            button_container = col2
        elif i % 4 == 2:
            button_container = col3
        else:
            button_container = col4
    
        button_clicked = button_container.button(word, key=word)
        if button_clicked:
            # 구분선 표시
            st.markdown("---")
            st.write(f"**{word}**")
            st.write(f"{definition}")
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# VxLAN 페이지




elif page == "Nexus VxLAN":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('Nexus VxLAN 설정 명령어')

#리스트 기능.
    table_names7 = list(VXLAN_table.keys())
    selected_table7 = st.selectbox("", VXLAN_table)

#테이블 시각화
    selected_df7 = VXLAN_table[selected_table7]
    st.dataframe(selected_df7, width=800)











#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ID = """

ID: student03

password: R@p@12#$

"""





st.sidebar.write('')
st.sidebar.write('')
st.sidebar.markdown(ID)
st.sidebar.write('')
st.sidebar.write('')




st.sidebar.markdown("[서브넷 계산 사이트](https://www.site24x7.com/tools/ipv4-subnetcalculator.html) ")
st.sidebar.markdown("[서브넷 비트 계산 사이트](https://www.calcip.com/) ")
st.sidebar.markdown("[Cisco 교육 사이트](https://www.netacad.com/portal/learning) ")


