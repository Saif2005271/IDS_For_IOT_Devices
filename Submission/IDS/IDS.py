import pyshark
import Check_IP as check_ip
import geocoder
import asyncio

def _read_pcap(interface, mode, alert_callback=None, stop_event=None):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    print(f"Starting sniffing on interface: {interface}...")
    
    try:
        capture = pyshark.LiveCapture(interface=interface)

        for pkt in capture.sniff_continuously():
            
            if stop_event and stop_event.is_set(): # True if stop_event.set() was called
                print("Stop signal received. Exiting IDS...")
                capture.close()
                break # Breaks from pkt loop to execute finally block

               #Extract IPs     
            if 'IP' in pkt:
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst 

                #Extract Ports
                src_port = "N/A"
                dst_port = "N/A"
                if 'TCP' in pkt:
                    src_port = pkt.tcp.srcport
                    dst_port = pkt.tcp.dstport
                elif 'UDP' in pkt:
                    src_port = pkt.udp.srcport
                    dst_port = pkt.udp.dstport
                
                print(f"Scanning: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")  # for debugging
            else:
                continue

            # Malicious check default values
            is_malicious = False
            malicious_source = "Unknown"
            attack_type = "N/A"
            comment = "N/A"
            
            # Mode 2: Offline Only
            if mode == 2:
                if check_ip.check_IP_offline(src_ip):
                    is_malicious = True
                    malicious_source = "Offline Blocklist"
                    attack_type = "Known Malicious IP"
                    comment = "Found in local Database"

            # Mode 1: Both (Offline First, then Online)
            elif mode == 1:
                if check_ip.check_IP_offline(src_ip):
                    is_malicious = True
                    malicious_source = "Offline Blocklist"
                    attack_type = "Known Malicious IP"
                    comment = "Found in local Database"
                else:
                    malicious, at_type, cmt = check_ip.check_IP_online(src_ip)
                    if malicious:
                        is_malicious = True
                        malicious_source = "Online API"
                        attack_type = at_type
                        comment = cmt

            # Mode 0: Online Only
            else:
                malicious, at_type, cmt = check_ip.check_IP_online(src_ip)
                if malicious:
                    is_malicious = True
                    malicious_source = "Online API"
                    attack_type = at_type
                    comment = cmt

            #  REPORTING 
            if is_malicious:
                country = "Unknown"
                try:
                    geo = geocoder.ip(src_ip)
                    if geo.ok: country = geo.country
                except: pass

                if alert_callback:
                    #log_alert function in dashboard
                    alert_callback(src_ip, dst_ip, src_port, dst_port, malicious_source, country, attack_type, comment) 
                
                print(f"[ALERT] {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Type: {attack_type}")
            
    except (KeyboardInterrupt, EOFError):
        pass
    except Exception as e:
        print(f"IDS Error: {e}")
    finally:
        if loop.is_running():
            loop.close()