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
    "설명": ["리스닝/러닝 단계를 건너뛰는 포트를 설정", "루트 브리지 변경을 방지하고 낮은 BPDU 브리지 차단", "다른 브리지의 BPDU를 차단하여 루트 브리지 변경 방지", "BPDU를 해당 포트로 송신하지 않음", "단방향 링크로 인한 루프 형성 방지", "vlan을 루트 브릿지로 설정", "vlan을 두번 째 브릿지로 설정"]
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

# Show 명령어
show_commands = {
    "명령어": ["show vlan", "show vtp", "show spanning-tree", "show ip route", "show running-config", "show interface", "show arp", "show history", "show vrrp", "show standby", "show ip", "show access-lists", "show adjacency", "show authentication", "show auto secure", "show bgp", "show cdp", "show cef", "show clock", "show cns", "show configuration", "show connection", "show crypto", "show controllers", "show dot11", "show dsl", "show eigrp", "show environment", "show event-history", "show firewall", "show flash", "show ftp", "show hardware", "show hosts", "show idprom", "show ip access-lists", "show ip accounting", "show ip arp", "show ip dhcp", "show ip eigrp", "show ip igmp", "show ip interface", "show ip nat", "show ip nbar", "show ip ospf", "show ip rsvp", "show ip wccp", "show ipx", "show isdn", "show key chain", "show ipv6", "show license", "show line", "show logging", "show mac-address-table", "show map-class", "show mls", "show multicast", "show network", "show nhrp", "show policy-map", "show ppp", "show process", "show protocol", "show queueing", "show redundancy", "show region", "show router", "show sccp", "show scheduler", "show sdm", "show session", "show snmp", "show ssh", "show stacks", "show startup-config", "show switch", "show tacacs+", "show tcp", "show tech-support", "show terminal", "show time", "show tftp", "show track", "show transceiver", "show version", "show voice", "show vpdn", "show vpn-sessiondb", "show wavelength"],
    "설명": ["VLAN 정보 표시", "VTP 설정 정보 표시", "스패닝 트리 프로토콜 정보 표시", "IP 라우팅 정보 표시", "현재 실행 중인 설정 표시", "인터페이스 상태 및 설정 표시", "ARP 테이블 정보 표시", "명령어 이력 표시", "VRRP 정보 표시", "Standby 프로토콜 정보 표시", "IP 프로토콜 정보 표시", "액세스 리스트 정보 표시", "인접 관계 정보 표시", "인증 상태 정보 표시", "자동 보안 설정 정보 표시", "BGP 정보 표시", "CDP 정보 표시", "CEF 정보 표시", "시계 설정 정보 표시", "CNS 정보 표시", "현재 설정 표시", "접속 정보 표시", "암호화 설정 정보 표시", "컨트롤러 설정 정보 표시", "Dot11 설정 정보 표시", "DSL 정보 표시", "EIGRP 정보 표시", "환경 설정 정보 표시", "이벤트 히스토리 정보 표시", "방화벽 설정 정보 표시", "플래시 메모리 정보 표시", "FTP 설정 정보 표시", "하드웨어 정보 표시", "호스트 정보 표시", "ID PROM 정보 표시", "IP 액세스 리스트 정보 표시", "IP 계정 정보 표시", "IP ARP 정보 표시", "IP DHCP 정보 표시", "IP EIGRP 정보 표시", "IP IGMP 정보 표시", "IP 인터페이스 정보 표시", "IP NAT 정보 표시", "IP NBAR 정보 표시", "IP OSPF 정보 표시", "IP RSVP 정보 표시", "IP WCCP 정보 표시", "IPX 정보 표시", "ISDN 정보 표시", "키 체인 정보 표시", "IPv6 정보 표시", "라이센스 정보 표시", "라인 설정 정보 표시", "로그 정보 표시", "MAC 주소 테이블 정보 표시", "맵 클래스 설정 정보 표시", "MLS 정보 표시", "멀티캐스트 정보 표시", "네트워크 정보 표시", "NHRP 정보 표시", "정책 맵 정보 표시", "PPP 정보 표시", "프로세스 정보 표시", "프로토콜 정보 표시", "큐잉 정보 표시", "중복 정보 표시", "리전 정보 표시", "라우터 정보 표시", "SCCP 정보 표시", "스케줄러 정보 표시", "SDM 정보 표시", "세션 정보 표시", "SNMP 정보 표시", "SSH 정보 표시", "스택 정보 표시", "시작 설정 정보 표시", "스위치 상태 정보 표시", "TACACS+ 정보 표시", "TCP 정보 표시", "기술 지원 정보 표시", "터미널 설정 정보 표시", "시간 정보 표시", "TFTP 정보 표시", "트랙 정보 표시", "트랜시버 정보 표시", "버전 정보 표시", "음성 정보 표시", "VPDN 정보 표시", "VPN 세션 데이터베이스 정보 표시", "파장 정보 표시"]
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
"루트 브릿지 보안 설정 명령어": root_bridge_security_df,
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
    "명령어": ["router ospf <아이디>", "network x.x.x.x <wildcard_mask> area <구역번호>","router-id x.x.x.x", "clear ip ospf process", "", "ip ospf cost", "auto-cost reference-bandwidth <value>", "ip ospf network point-to-point", "", "default-information originate", "default-information originate always", "neighbor <ip> default-originate", "", "passive-interfce <인터페이스>", "passive-interface default", "no passive-interface <인터페이스>", "", "redistribute [재분배 할 프로토콜 명] [프로토콜ID] metric [값]", "redistribute <재분배 대상 프로토콜> subnets", "redistribute <재분배 대상> subnets metric-type <타입번호>","", "show ip ospf neighbor", "show ip protocols", "show ip route ospf", "show run | section ospf", "show ip ospf interface brief", "show ip ospf database"],
    "설명": ["ospf를 실행 후 아이디 번호를 지정(본인만 인지함)", "x.x.x.x = 내 hello 메세지 보낼 인터페이스 IP | 와일드카드 마스크 | 연결할 구역번호", "라우터ID 변경 명령어 (IP 형식의 ID지만 통신과는 상관 없음)", "라우터ID 변경을 리셋으로 적용", "", "OSPF cost 변경 명령어", "OSPF에서 자동 비용 계산에 사용되는 참조 대역폭 설정", "인터페이스를 P2P상태로 변경 (DR/BDR선정x)", "", "라우팅 테이블에 Default Route가 있는 경우 광고", "라우팅 테이블에 Default Route가 없어도 광고", "특정 Neighbor에게 Default Route가 나라고 광고", "", "이 방향으로는 Hello메세지를 보내지 말라는 명령어(광고는 실행함)", "모든 인터페이스에 Hello메세지를 보내지 않음", "이 인터페이스는 Hello 메세지를 보냄", "", "재분배 할 프로토콜을 명시하고 어떤 값으로 변경할 것인지 입력", "재분배 대상 프로토콜의 라우팅 테이블을 재분배하여 가져오는 명령어 (subnets를 써야 서브넷 값까지 가져옴)", "재분배 대상의 타입을 결정하여 재분배", "", "OSPF 이웃 목록 표시", "라우팅 프로토콜 설정과 관련된 정보 표시", "OSPF로 학습한 라우팅 테이블 표시", "현재 라우터의 구성에서 OSPF 구성 섹션 표시", "OSPF 인터페이스의 간략한 상태 표시", "OSPF 데이터베이스 정보 표시"]
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
    "설명":["Local AS 번호를 입력하여 BGP를 작동", "Neighbor를 맺고 싶은 상대의 IP와 AS를 입력하여 Neighbor 관계 요청", "Neighbor를 맺을 때 설정할 비밀번호", "광고하고 싶은 IP를 테이블에 등록", "", "BGP 이웃 관계 상세 정보 확인", "BGP 테이블 정보 확인", "BGP 테이블에서 도착지로 가는 경로 확인"]
}

#iBGP
iBGP = {
    "명령어":["router bgp <Local AS-num>", "neighbor <상대 Loopback IP> remote-as <상대 as-num>", "neighbor <상대 Loopback IP> update-source <내 Loopback 인터페이스>", "ip route <summary> <mask> null 0", "nighbor <iBGP Neighbor IP> next-hop-self", "neighbor <Neighbor IP> route-reflector-client", "", "show ip bgp summary", "show ip bgp", "show ip bgp <도착지 IP>"],
    "설명":["Local AS 번호를 입력하여 BGP를 작동", "Neighbor를 맺고 싶은 상대의 Loopback IP와 AS를 입력하여 Neighbor 관계 요청", "내 소스 IP를 Loopback으로 수정하고 상대의Loopback IP를 통해 iBGP 이웃 관계를 맺는 설정.", "광고하려는 라우터에서 빈 공간에 축약 라우팅 정보 등록(null 0 자료 참고)", "eBGP 역할을 하는 라우터의 iBGP 설정 (Next-Hop Self 자료 참고)", "RR 기기에서 RRC 지정(RRC는 RR과 네이버만 맺으면 됨)", "", "BGP 이웃 관계 상세 정보 확인", "BGP 테이블 정보 확인", "BGP 테이블에서 도착지로 가는 경로 확인"]
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



# 테이블 데이터 정의
r_tables = {"스태틱 라우팅 명령어": static_route_df,
           "OSPF 명령어": ospf_commands,
           "standard_ACL 명령어": standard_ACL,
           "Extended_ACL 명령어":Extended_ACL,
            "eBGP 명령어" : eBGP,
            "iBGP 명령어": iBGP,
            "Inside Static NAT 명령어": in_NAT_commands,
            "Outside Static NAT 명령어": out_NAT_commands,
            "Dynamic NAT 명령어": D_NAT_commands,
            "PAT 명령어": PAT_commands,
            "ip 연결 확인 명령어": ip_df,
           "show 명령어": show}














text2 = """
**라우터**는 패킷을 읽고 목적지 IP 주소를 기반으로 최적의 경로를 결정합니다. 

그리고 그 경로에 따라 다음 라우터로 패킷을 전송합니다.

이러한 과정을 통해 데이터가 출발지에서 목적지로 안전하고 효율적으로 전달됩니다.
"""






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
        "(config-if)# nameif <name>",
        "(config-if)# ip address <IP> <netmask>",
        "(config-if)# security-level <1~100>",
        "same-security-traffic permit inter-interface",
        "(config-if)# no shutdown"
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



# 테이블 데이터 정의
F_tables = {"방화벽 기본 명령어": f_command,
           "L3 명령어": L3_command,
            "OSPF 명령어": OSPF_command,
            "SSH 명령어": SSH_command,
            "NameIF 명령어": NameIF_command,
            "ASDM 이미지 다운로드 명령어": ASDM_command,
            "Connect Table 명령어": C_Table_command,
            "ACL 명령어": F_ACL_command
           }





#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------






# 커스텀 워닝 문구
def custom_warning(message):
    st.markdown(f'<div style="color: orange; font-size: large;">{message}</div>', unsafe_allow_html=True)



# 이미지를 URL로 추가하는 코드
image_url = "https://github.com/pDuKyu/switch/blob/main/20210112_163404.jpg?raw=true"
use_column_width = True
caption=''
st.sidebar.image(image_url, caption=caption, use_column_width=use_column_width)


# 오늘 날짜 가져오기
today_date = datetime.today().strftime('%Y-%m-%d')
st.sidebar.write(f"오늘은 {today_date}일 입니다!")



# 사이드바에 버튼 추가
page = st.sidebar.selectbox("명령어를 확인할 기기를 선택해주세요.", ["Switch", "Router", "FireWall"])



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
    custom_warning("알아야 하는 스위치 용어 <br><br> 이더넷 헤더, ARP프로토콜, LAN, VLAN, 트렁크, VTP, Native VLAN, Allowed VLAN, Spanning-Tree, BPDU, PVST, RPVST, Etherchannel, SVI, Routedport, portchannel, HSRP, VRRP")



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

    st.success(text2)


#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 라우터 페이지
elif page == "FireWall":
    # 네트워크 설정 명령어로 대제목 설정
    st.title('방화벽 설정 명령어')

#리스트 기능
    table_names3 = list(F_tables.keys())
    selected_table3 = st.selectbox("", table_names3)  

#테이블 시각화
    selected_df3 = F_tables[selected_table3]
    st.dataframe(selected_df3, width=800)

    

    




















st.sidebar.write('')
st.sidebar.write('')
st.sidebar.write('')
st.sidebar.write('')


st.sidebar.markdown("[서브넷 계산 사이트](https://www.site24x7.com/tools/ipv4-subnetcalculator.html) ")
st.sidebar.markdown("[서브넷 비트 계산 사이트](https://www.calcip.com/) ")
st.sidebar.markdown("[Cisco 교육 사이트](https://www.netacad.com/portal/learning) ")


