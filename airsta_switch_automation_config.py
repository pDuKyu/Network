import streamlit as st
from netmiko import ConnectHandler
import ipaddress
import paramiko  # Import paramiko for SSH tunneling

# Sidebar image
st.sidebar.image("https://raw.githubusercontent.com/pDuKyu/Network/main/arista-center.jpg", use_column_width=True)

# CSS for background and styling
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
    background-color: rgba(0, 0, 0, 0.5); /* Dark overlay */
    filter: blur(5px); /* Blur effect */
    z-index: 1;
    pointer-events: none;
}

.stApp > div {
    z-index: 2; /* Ensures content is above overlay */
    position: relative;
}
</style>
'''

st.markdown(page_bg_img, unsafe_allow_html=True)

def setup_ssh_tunnel(ip, ssh_username, ssh_password, ssh_port=22, local_port=10022):
    # Setup SSH tunnel using paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(ip, username=ssh_username, password=ssh_password, port=ssh_port)
        transport = client.get_transport()
        local_addr = ('localhost', local_port)
        remote_addr = (ip, ssh_port)
        
        # Setup a forwarding channel (reverse tunnel)
        transport.request_port_forward(local_addr, remote_addr)
        st.success(f"SSH tunnel established on port {local_port}")
        return transport
    except Exception as e:
        st.error(f"Failed to establish SSH tunnel: {e}")
        return None

def connect_and_run_commands(ip, username, password, enable_password, commands, ssh_tunnel=None):
    device = {
        'device_type': 'cisco_ios',
        'ip': 'localhost' if ssh_tunnel else ip,  # Use localhost if tunneling
        'username': username,
        'password': password,
        'port': 10022 if ssh_tunnel else 22,  # Local port if tunneling
    }

    results = {}

    try:
        with ConnectHandler(**device) as net_connect:
            if enable_password:
                net_connect.enable()

            for command in commands:
                output = net_connect.send_command(command)
                results[command] = output

        return results

    except Exception as e:
        return str(e)

def connect_and_run_commands_arista(ip, username, password, enable_password, commands, ssh_tunnel=None):
    device = {
        'device_type': 'arista_eos',
        'ip': 'localhost' if ssh_tunnel else ip,
        'username': username,
        'password': password,
        'port': 10022 if ssh_tunnel else 22,
    }

    results = {}

    try:
        with ConnectHandler(**device) as net_connect:
            if enable_password:
                net_connect.enable()

            for command in commands:
                output = net_connect.send_command(command)
                results[command] = output

        return results

    except Exception as e:
        return str(e)

# Device basic show Command page
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
                ssh_tunnel = setup_ssh_tunnel(ip, ssh_username=username, ssh_password=password)
                if ssh_tunnel:
                    results = connect_and_run_commands(ip, username, password, enable_password, commands, ssh_tunnel)
                    ssh_tunnel.close()
                else:
                    st.error("SSH tunnel setup failed.")

                if isinstance(results, dict):
                    for command, output in results.items():
                        st.markdown(f"**Command: `{command}`**")
                        st.text_area("", output, height=200)
                        st.markdown("***")
                else:
                    st.error(f"Failed to retrieve data from the device {ip}: {results}")
        else:
            st.warning("Please fill in all the fields and select at least one command.")

# IP Configurator page
def configure_ips(ip, username, password, enable_password, interfaces, starting_cidr, description):
    device = {
        'device_type': 'cisco_ios',
        'ip': 'localhost',
        'username': username,
        'password': password,
        'port': 10022,  # Local port if tunneling
    }

    try:
        ssh_tunnel = setup_ssh_tunnel(ip, ssh_username=username, ssh_password=password)
        if ssh_tunnel:
            with ConnectHandler(**device) as net_connect:
                if enable_password:
                    net_connect.enable()

                net_connect.config_mode()

                config_commands = []

                network = ipaddress.IPv4Network(starting_cidr, strict=False)
                subnet_mask = str(network.netmask)
                base_ip = int(network.network_address)

                for index, interface in enumerate(interfaces):
                    new_network_ip = ipaddress.IPv4Address(base_ip + index * network.num_addresses)
                    config_ip = str(new_network_ip)

                    config_commands.append(f"interface {interface}")
                    config_commands.append("no switchport")
                    config_commands.append(f"ip address {config_ip} {subnet_mask}")

                    if description:
                        config_commands.append(f"description {description}")

                output = net_connect.send_config_set(config_commands)
                st.text(output)

                st.success("IP configuration complete.")
            ssh_tunnel.close()
        else:
            st.error("SSH tunnel setup failed.")
    except Exception as e:
        st.error(f"Failed to configure IP on the device {ip}: {e}")

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

# VXLAN Troubleshooting page
def vxlan_troubleshooting():
    st.title("VXLAN Troubleshooting")

    ip = st.text_input("Device IP", "")
    username = st.text_input("Username", "")
    password = st.text_input("Password", "", type="password")
    enable_password = st.text_input("Enable Password", "", type="password")

    commands = st.multiselect(
        "Select VXLAN Troubleshooting Commands",
        [
            "show interfaces vxlan 1", 
            "show vxlan vtep", 
            "show vxlan vtep detail", 
            "show vxlan address-table", 
            "show vxlan flood vtep", 
            "show interfaces vxlan 1 counters"
        ]
    )

    if st.button("Run VXLAN Commands"):
        if ip and username and password and commands:
            st.subheader(f"Results for {ip}")
            ssh_tunnel = setup_ssh_tunnel(ip, ssh_username=username, ssh_password=password)
            if ssh_tunnel:
                results = connect_and_run_commands_arista(ip, username, password, enable_password, commands, ssh_tunnel)
                ssh_tunnel.close()
            else:
                st.error("SSH tunnel setup failed.")

            if isinstance(results, dict):
                for command, output in results.items():
                    st.markdown(f"**Command: `{command}`**")
                    st.text_area("", output, height=200)
                    st.markdown("***")
            else:
                st.error(f"Failed to retrieve data from the device {ip}: {results}")
        else:
            st.warning("Please fill in all the fields and select at least one command.")

# Page selector
page = st.sidebar.selectbox("Select a page", ("Device basic show Command", "IP Configurator", "VXLAN Troubleshooting"))

if page == "Device basic show Command":
    command_executor()
elif page == "IP Configurator":
    ip_configurator()
else:
    vxlan_troubleshooting()
