import streamlit as st
import pandas as pd

# 네트워크 설정 명령어로 대제목 설정
st.title('네트워크 설정 명령어')

def show_info_message(message):
    """
    사용자에게 안내 메시지를 보여주는 함수.

    Parameters:
    message (str): 사용자에게 보여줄 메시지.
    """
    st.info(message)

def main():

    # 사용자에게 보여줄 메시지
    message = "환영합니다! 이 페이지는 네트워크 기기의 명령어를 안내하는 페이지입니다."

    # 안내 메시지를 보여주는 함수 호출
    show_info_message(message)

if __name__ == '__main__':
    main()
    
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
    "명령어": ["show vlan", "vlan 2", "name computers", "interface ~", "switchport mode access", "switchport access vlan 2", "show interfaces '포트번호' switchport"],
    "설명": ["현재 VLAN 설정을 표시", "VLAN 번호가 2인 VLAN을 생성", "VLAN의 이름을 'computers'로 설정", "~ 인터페이스에 접근", "해당 스위치포트를 Access 모드로 설정", "해당 스위치포트 Access를 VLAN 2로 지정", "지정된 포트의 스위치포트 설정 정보를 표시"]
}

# VTP 명령어
vtp_commands = {
    "명령어": ["vtp mode {server/client/transparent}", "vtp domain domain-name", "vtp password password", "vtp pruning", "vtp version {1/2/3}", "vtp file {filename}", "show vtp status", "show vtp counters", "clear vtp counters", "clear vtp counters {interface}"],
    "설명": ["VTP 모드 설정", "VTP 도메인 이름 설정", "VTP 도메인 옵션 비밀번호 설정(server의 설정을 client가 적용시에도 사용)", "VTP Pruning 활성화", "VTP 버전 설정", "VTP 설정 파일 저장 또는 불러오기", "현재 VTP 설정 상태 표시", "VTP 정보 교환에 대한 통계 표시", "VTP 통계 재설정", "특정 인터페이스의 VTP 통계 재설정"]
}

# 트렁크 프로토콜 명령어
trunk_protocol_data = {
    "명령어": ["interface <인터페이스 이름>", "switchport mode trunk", "switchport trunk allowed vlan <VLAN 번호>", "switchport mode trunk vlan add <VLAN 번호>", "switchport trunk native vlan <VLAN 번호>"],
    "설명": ["설정하려는 인터페이스로 이동", "해당 인터페이스를 트렁크 모드로 설정", "트렁크에서 허용할 VLAN을 지정", "트렁크에 VLAN 추가", "해당 인터페이스의 네이티브 VLAN을 설정"]
}

# 부트 이미지 변경 명령어
boot_image_change = {
    "명령어": ["dir", "copy tftp: flash", "dir", "conf t", "boot system flash:파일명", "show boot", "wr", "reload"],
    "설명": ["파일 경로 확인", "TFTP 서버에서 이미지 파일을 복사하여 라우터의 플래시 메모리에 저장", "파일 재확인", "설정 터미널 열기", "라우터가 부팅할 때 사용할 이미지를 지정", "부팅 이미지 지정 확인", "startup-running에 덮어쓰기", "재시작"]
}

# 로그 저장 서버 명령어
server_logs = {
    "명령어": ["configure terminal", "logging host 000.000.000.000", "logging trap debugging", "wr"],
    "설명": ["관리자 모드 진입", "로그를 저장할 서버의 IP 설정", "디버깅 로그 저장 설정", "설정 저장"]
}

# 원격 접속을 위한 스위치 IP 할당 명령어
remote_access_switch = {
    "명령어": ["conf t", "interface vlan 1", "ip address [IP 주소] [서브넷 마스크]", "no shutdown", "end", "show ip interface brief", "wr", "ip default-gateway x.x.x.x"],
    "설명": ["구성 모드 진입", "VLAN 1 인터페이스 선택", "IP 주소와 서브넷 마스크 할당", "인터페이스 활성화", "설정 모드 종료", "인터페이스 상태 확인", "설정 저장", "게이트웨이 설정"]
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
hsrp_data = {"명령어": ["interface vlan 10", "ip address 10.1.10.252 255.255.255.0", "standby 10 ip 10.1.10.254", "standby 10 preempt", "standby 10 priority 110", "standby [그룹명] timers ? ?", "show standby brief", "show standby"], 
             "설명": ["VLAN 10에 대한 인터페이스 설정을 시작", "VLAN 10에 IP 주소 10.1.10.252를 할당하고 서브넷 마스크를 255.255.255.0으로 설정", "가상 게이트웨이의 IP 주소를 10.1.10.254로 설정", "게이트웨이 장비가 다시 활성화될 때 자동으로 우선순위를 갖게 함", "가상 게이트웨이에 우선순위를 110으로 설정. 높은 우선순위를 갖는 장비가 active, 낮으면 standby", "이중화된 기기들 끼리 정상 가동하는지 확인 (첫 숫자는 hello 타임, 둘째 숫자는 대기 시간)", "간략한 가상 게이트웨이 정보 확인", "상세한 가상 게이트웨이 정보 확인"]
}

# VRRP Master/Worker 명령어 데이터
vrrp_data = {"명령어": ["interface vlan 10", "ip address 10.1.10.252 255.255.255.0", "vrrp10 ip 10.1.10.254", "vrrp 10 priority 110", "show vrrp brief", "show vrrp"], 
             "설명": ["VLAN 10 인터페이스 설정 시작", "VLAN 10에 IP 주소를 설정", "VRRP 그룹 10의 가상 IP 주소를 설정", "VRRP 그룹 10에서 우선순위를 110으로 설정(높은 값이 Active)", "간략한 VRRP 정보 표시", "상세한 VRRP 정보 표시"]
}

# Show 명령어
show_commands = {
    "명령어": ["show vlan", "show vtp", "show spanning-tree", "show ip route", "show running-config", "show interface", "show arp", "show history", "show vrrp", "show standby", "show ip", "show access-lists", "show adjacency", "show authentication", "show auto secure", "show bgp", "show cdp", "show cef", "show clock", "show cns", "show configuration", "show connection", "show crypto", "show controllers", "show dot11", "show dsl", "show eigrp", "show environment", "show event-history", "show firewall", "show flash", "show ftp", "show hardware", "show hosts", "show idprom", "show ip access-lists", "show ip accounting", "show ip arp", "show ip dhcp", "show ip eigrp", "show ip igmp", "show ip interface", "show ip nat", "show ip nbar", "show ip ospf", "show ip rsvp", "show ip wccp", "show ipx", "show isdn", "show key chain", "show ipv6", "show license", "show line", "show logging", "show mac-address-table", "show map-class", "show mls", "show multicast", "show network", "show nhrp", "show policy-map", "show ppp", "show process", "show protocol", "show queueing", "show redundancy", "show region", "show router", "show sccp", "show scheduler", "show sdm", "show session", "show snmp", "show ssh", "show stacks", "show startup-config", "show switch", "show tacacs+", "show tcp", "show tech-support", "show terminal", "show time", "show tftp", "show track", "show transceiver", "show version", "show voice", "show vpdn", "show vpn-sessiondb", "show wavelength"],
    "설명": ["VLAN 정보 표시", "VTP 설정 정보 표시", "스패닝 트리 프로토콜 정보 표시", "IP 라우팅 정보 표시", "현재 실행 중인 설정 표시", "인터페이스 상태 및 설정 표시", "ARP 테이블 정보 표시", "명령어 이력 표시", "VRRP 정보 표시", "Standby 프로토콜 정보 표시", "IP 프로토콜 정보 표시", "액세스 리스트 정보 표시", "인접 관계 정보 표시", "인증 상태 정보 표시", "자동 보안 설정 정보 표시", "BGP 정보 표시", "CDP 정보 표시", "CEF 정보 표시", "시계 설정 정보 표시", "CNS 정보 표시", "현재 설정 표시", "접속 정보 표시", "암호화 설정 정보 표시", "컨트롤러 설정 정보 표시", "Dot11 설정 정보 표시", "DSL 정보 표시", "EIGRP 정보 표시", "환경 설정 정보 표시", "이벤트 히스토리 정보 표시", "방화벽 설정 정보 표시", "플래시 메모리 정보 표시", "FTP 설정 정보 표시", "하드웨어 정보 표시", "호스트 정보 표시", "ID PROM 정보 표시", "IP 액세스 리스트 정보 표시", "IP 계정 정보 표시", "IP ARP 정보 표시", "IP DHCP 정보 표시", "IP EIGRP 정보 표시", "IP IGMP 정보 표시", "IP 인터페이스 정보 표시", "IP NAT 정보 표시", "IP NBAR 정보 표시", "IP OSPF 정보 표시", "IP RSVP 정보 표시", "IP WCCP 정보 표시", "IPX 정보 표시", "ISDN 정보 표시", "키 체인 정보 표시", "IPv6 정보 표시", "라이센스 정보 표시", "라인 설정 정보 표시", "로그 정보 표시", "MAC 주소 테이블 정보 표시", "맵 클래스 설정 정보 표시", "MLS 정보 표시", "멀티캐스트 정보 표시", "네트워크 정보 표시", "NHRP 정보 표시", "정책 맵 정보 표시", "PPP 정보 표시", "프로세스 정보 표시", "프로토콜 정보 표시", "큐잉 정보 표시", "중복 정보 표시", "리전 정보 표시", "라우터 정보 표시", "SCCP 정보 표시", "스케줄러 정보 표시", "SDM 정보 표시", "세션 정보 표시", "SNMP 정보 표시", "SSH 정보 표시", "스택 정보 표시", "시작 설정 정보 표시", "스위치 상태 정보 표시", "TACACS+ 정보 표시", "TCP 정보 표시", "기술 지원 정보 표시", "터미널 설정 정보 표시", "시간 정보 표시", "TFTP 정보 표시", "트랙 정보 표시", "트랜시버 정보 표시", "버전 정보 표시", "음성 정보 표시", "VPDN 정보 표시", "VPN 세션 데이터베이스 정보 표시", "파장 정보 표시"]
}










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


table_names = list(tables.keys())
selected_table = st.selectbox("Switch 명령어 리스트", table_names)




# 선택한 테이블의 데이터 표시
selected_df = tables[selected_table]
st.dataframe(selected_df, width=800)


# 이미지를 URL로 추가합니다.
st.image("https://github.com/pDuKyu/switch/blob/main/20210112_163404.jpg?raw=true", caption="이미지 캡션", use_column_width=True)

# # 테이블 표시 - 기본설정 명령어
# st.subheader('show 명령어')
# st.table(show_commands_df)

# # 테이블 표시 - 기본설정 명령어
# st.subheader('기본설정 명령어')
# st.table(basic_df)

# # 테이블 표시 - 원격 접근 보안 설정 명령어
# st.subheader('원격 접근 보안 설정 명령어')
# st.table(remote_access_df)

# # VLAN 설정 명령어
# st.subheader('VLAN 설정 명령어')
# st.table(vlan_df)

# # 트렁크 프로토콜 설정 명령어
# st.subheader('트렁크 프로토콜 설정 명령어')
# st.table(trunk_protocol_df)

# # 트렁크 프로토콜 설정 명령어
# st.subheader('부트 이미지 설정 명령어')
# st.table(boot_image_change_df)

# # 로그 저장 서버 명령어
# st.subheader('로그 저장 서버 명령어')
# st.table(bserver_logs_df)

# # 로그 저장 서버 명령어
# st.subheader('원격 접속을 위한 스위치 IP 할당 명령어')
# st.table(remote_access_switch_df)

# # 트래킹 설정 명령어
# st.subheader('트래킹 설정 명령어')
# st.table(tracking_commands_df)

# # 트렁크 설정 명령어
# st.subheader('트렁크 설정 명령어')
# st.table(trunk_protocol_commands_df)

# # 네이티브 vlan 명령어
# st.subheader('네이티브 vlan 설정 명령어')
# st.table(native_vlan_commands_df)

# # STP 설정
# st.subheader('STP 설정 명령어')
# st.table(stp_settings_df)

# # 루트 브릿지 설정
# st.subheader('루트 브릿지 설정 명령어')
# st.table(root_bridge_security_df)

# # 트래킹 설정
# st.subheader('트래킹 설정 명령어')
# st.table(tracking_data_df)

# # 트러블 슈팅 명령어
# st.subheader('트러블 슈팅 명령어')
# st.table(trouble_shooting_data_df)

# # 이더채널 설정 명령어
# st.subheader('이더채널 설정 명령어')
# st.table(etherchannel_data_df)

# # 라우티드 포트 설정 명령어
# st.subheader('라우티드 포트 설정 명령어')
# st.table(routed_port_data_df)

# # SVI 설정 명령어 데이터
# st.subheader('SVI 설정 명령어')
# st.table(svi_data_df)

# # HSRP 설정 명령어 데이터
# st.subheader('HSRP 설정 명령어')
# st.table(hsrp_data_df)

# # VRRP 설정 명령어 데이터
# st.subheader('VRRP 설정 명령어')
# st.table(vrrp_data_df)
