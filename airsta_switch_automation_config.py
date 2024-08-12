import streamlit as st
from netmiko import ConnectHandler
import ipaddress

# 사이드바에 이미지를 추가
st.sidebar.image("https://raw.githubusercontent.com/pDuKyu/Network/main/arista-center.jpg", use_column_width=True)

# CSS를 이용하여 상단과 하단의 여백을 제거하고, 페이지를 전체 화면으로 확장하며, 배경에 어둡고 블러 처리된 오버레이를 추가
page_bg_img = '''
<style>
.stApp {
    background-image: url("https://raw.githubusercontent.com/pDuKyu/Network/main/shutterstock_1696920283-2.jpg");
    background-size: cover;
    background-repeat: no-repeat;
    background-attachment: fixed;
    height: 100vh;
    margin: 0;
    padding: 0;
    position: relative;
}

.block-container {
    padding-top: 0;
    padding-bottom: 0;
    margin-top: 0;
    margin-bottom: 0;
    height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.stApp::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5); /* 어두운 오버레이 추가 */
    filter: blur(5px); /* 배경 블러 처리 */
    z-index: 1; /* 오버레이를 텍스트 뒤로 보내기 */
    pointer-events: none; /* 오버레이가 상호작용을 방해하지 않도록 설정 */
}

.stApp > div {
    z-index: 2; /* 텍스트와 입력 필드가 오버레이 위에 오도록 설정 */
    position: relative;
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
