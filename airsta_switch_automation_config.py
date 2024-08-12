import streamlit as st
from netmiko import ConnectHandler
import ipaddress

# 사이드바에 이미지를 추가 (원래 상태로 복구)
st.sidebar.image("https://raw.githubusercontent.com/pDuKyu/Network/main/arista-center.jpg", use_column_width=True)

# CSS를 이용하여 메인 페이지 배경에 이미지를 설정하고, 텍스트 필드의 스타일을 개선
page_bg_img = '''
<style>
.stApp {
    background-image: url("https://raw.githubusercontent.com/pDuKyu/Network/main/shutterstock_1696920283-2.webp");
    background-size: cover;
    background-repeat: no-repeat;
    background-attachment: fixed;
}

/* 텍스트와 입력 필드의 스타일 개선 */
div[data-testid="stMarkdownContainer"] {
    background-color: rgba(0, 0, 0, 0.6); /* 반투명한 어두운 배경 */
    padding: 10px;
    border-radius: 8px;
    color: #ffffff; /* 밝은 글씨 색 */
    font-family: Arial, sans-serif; /* 폰트 변경 */
}

.stTextInput, .stTextArea, .stSelectbox, .stMultiselect {
    background-color: rgba(255, 255, 255, 0.8); /* 입력 필드의 배경을 약간 밝게 */
    color: #000000; /* 입력 필드의 글씨 색상 */
    border: none; /* 테두리 제거 */
    border-radius: 8px; /* 모서리 둥글게 */
    padding: 10px; /* 패딩 추가 */
    font-family: Arial, sans-serif; /* 폰트 변경 */
    margin-bottom: 10px; /* 하단 여백 추가 */
}

.stButton button {
    background-color: #1f77b4; /* 버튼 배경색 */
    color: #ffffff; /* 버튼 텍스트 색상 */
    border: none; /* 테두리 제거 */
    border-radius: 8px; /* 버튼 모서리 둥글게 */
    padding: 10px 20px; /* 패딩 추가 */
    font-family: Arial, sans-serif; /* 폰트 변경 */
    font-size: 16px; /* 버튼 텍스트 크기 조정 */
    margin-top: 20px; /* 상단 여백 추가 */
    transition: background-color 0.3s ease; /* 호버 효과 */
}

.stButton button:hover {
    background-color: #1361a3; /* 호버 시 버튼 색상 변경 */
}
</style>
'''

st.markdown(page_bg_img, unsafe_allow_html=True)

# 첫 번째 페이지: Device basic show Command
def command_executor():
    st.title("Device basic show Command")

    ips = st.text_area("IP Addresses (comma-separated)", "")
    username = st.text_input("Username", "")
    password = st.text_input("Password", "", type="password")
    enable_password = st.text_input("Enable Password", "", type="password")

    commands = st.multiselect(
        "Select the commands to run",
        ["show interfaces status", "show ip interface brief", "show version", "show running-config"]
    )

    if st.button("Run Commands"):
        if ips and username and password and commands:
            ip_list = [ip.strip() for ip in ips.split(",")]

            for ip in ip_list:
                st.subheader(f"Results for {ip}")
                results = connect_and_run_commands(ip, username, password, enable_password, commands)

                if isinstance(results, dict):
                    for command, output in results.items():
                        st.markdown(f"**Command: `{command}`**")  # 명령어 제목을 굵게 표시
                        st.text_area("", output, height=200)  # 결과를 상자 안에 표시
                        st.markdown("***")  # 구분선 추가 (더 두껍게)
                else:
                    st.error(f"Failed to retrieve data from the device {ip}: {results}")
        else:
            st.warning("Please fill in all the fields and select at least one command.")

def connect_and_run_commands(ip, username, password, enable_password, commands):
    # Netmiko 연결 설정
    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
    }

    results = {}

    try:
        # 장비에 연결
        with ConnectHandler(**device) as net_connect:
            # Enable mode로 전환 (enable_password가 있는 경우에만)
            if enable_password:
                net_connect.enable()

            # 선택한 명령어 실행
            for command in commands:
                output = net_connect.send_command(command)
                results[command] = output

        return results

    except Exception as e:
        return str(e)

# 두 번째 페이지: IP 설정
def configure_ips(ip, username, password, enable_password, interfaces, starting_cidr, description):
    device = {
        'device_type': 'cisco_ios',
        'ip': ip,
        'username': username,
        'password': password,
    }

    try:
        with ConnectHandler(**device) as net_connect:
            # Enable mode로 전환 (enable_password가 있는 경우에만)
            if enable_password:
                net_connect.enable()

            net_connect.config_mode()

            config_commands = []

            # 입력된 CIDR을 기반으로 서브넷 마스크와 시작 IP 계산
            network = ipaddress.IPv4Network(starting_cidr, strict=False)
            subnet_mask = str(network.netmask)
            base_ip = int(network.network_address)

            # 각 인터페이스에 대해 동일한 description 적용
            for index, interface in enumerate(interfaces):
                new_network_ip = ipaddress.IPv4Address(base_ip + index * network.num_addresses)
                config_ip = str(new_network_ip)  # 네트워크 주소 그대로 사용

                config_commands.append(f"interface {interface}")
                config_commands.append("no switchport")
                config_commands.append(f"ip address {config_ip} {subnet_mask}")

                if description:  # description이 입력된 경우
                    config_commands.append(f"description {description}")

            # 생성된 모든 명령어를 한 번에 전송
            output = net_connect.send_config_set(config_commands)
            st.text(output)

            st.success("IP configuration complete.")
    except Exception as e:
        st.error(f"Failed to configure IP on the device {ip}: {e}")

# IP Configurator 페이지
def ip_configurator():
    st.title("Interface IP Configurator")

    ip = st.text_input("Device IP", "")
    username = st.text_input("Username", "")
    password = st.text_input("Password", "", type="password")
    enable_password = st.text_input("Enable Password", "", type="password")
    interfaces = st.text_area("Interfaces (comma-separated, e.g., GigabitEthernet0/1, GigabitEthernet0/2)", "")
    description = st.text_input("Description (e.g., 'Link to Router', 'Uplink to Switch')", "")
    starting_cidr = st.text_input("Starting IP with CIDR (e.g., 192.168.1.1/24)", "")

    if st.button("Configure IPs"):
        if ip and username and password and interfaces and starting_cidr:
            interface_list = [intf.strip() for intf in interfaces.split(",")]
            configure_ips(ip, username, password, enable_password, interface_list, starting_cidr, description)
        else:
            st.warning("Please fill in all the fields.")

# 세 번째 페이지: VXLAN 트러블슈팅 (Arista EOS 명령어 사용)
def vxlan_troubleshooting():
    st.title("VXLAN Troubleshooting")

    ip = st.text_input("Device IP", "")
    username = st.text_input("Username", "")
    password = st.text_input("Password", "", type="password")
    enable_password = st.text_input("Enable Password", "", type="password")

    # 필요 없는 명령어를 제거하고, 명령어를 수정한 VXLAN 관련 Arista EOS 명령어 리스트
    commands = st.multiselect(
        "Select VXLAN Troubleshooting Commands",
        [
            "show interfaces vxlan 1", 
            "show vxlan vtep", 
            "show vxlan vtep detail",  # 수정됨
            "show vxlan address-table",  # 수정됨
            "show vxlan flood vtep", 
            "show interfaces vxlan 1 counters"
        ]
    )

    if st.button("Run VXLAN Commands"):
        if ip and username and password and commands:
            st.subheader(f"Results for {ip}")
            results = connect_and_run_commands_arista(ip, username, password, enable_password, commands)

            if isinstance(results, dict):
                for command, output in results.items():
                    st.markdown(f"**Command: `{command}`**")  # 명령어 제목을 굵게 표시
                    st.text_area("", output, height=200)  # 결과를 상자 안에 표시
                    st.markdown("***")  # 구분선 추가 (더 두껍게)
            else:
                st.error(f"Failed to retrieve data from the device {ip}: {results}")
        else:
            st.warning("Please fill in all the fields and select at least one command.")

def connect_and_run_commands_arista(ip, username, password, enable_password, commands):
    # Netmiko 연결 설정 (Arista EOS 장비용)
    device = {
        'device_type': 'arista_eos',
        'ip': ip,
        'username': username,
        'password': password,
    }

    results = {}

    try:
        # 장비에 연결
        with ConnectHandler(**device) as net_connect:
            # Enable mode로 전환 (enable_password가 있는 경우에만)
            if enable_password:
                net_connect.enable()

            # 선택한 명령어 실행
            for command in commands:
                output = net_connect.send_command(command)
                results[command] = output

        return results

    except Exception as e:
        return str(e)

# 페이지 선택
page = st.sidebar.selectbox("Select a page", ("Device basic show Command", "IP Configurator", "VXLAN Troubleshooting"))

if page == "Device basic show Command":
    command_executor()
elif page == "IP Configurator":
    ip_configurator()
else:
    vxlan_troubleshooting()
