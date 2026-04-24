import httpx

def run_differential_fuzzer(target):
    print(f"[*] Initializing Differential Engine against: {target}")
    
    # 1. Baseline Request: Standard, legal headers
    headers_baseline = {
        "User-Agent": "Wafmancer-Fuzzer/1.0",
        "Accept": "*/*"
    }
    
    # 2. Anomalous Request: Notice the trailing space in 'X-Bypass-Test '
    # This specifically tests if the Edge WAF and Origin Server parse spaces differently.
    headers_anomalous = {
        "User-Agent": "Wafmancer-Fuzzer/1.0",
        "Accept": "*/*",
        "X-Bypass-Test ": "DiscrepancyCheck" 
    }

    print("[*] Launching HTTP/2 probe sequence...")

    try:
        with httpx.Client(http2=True, verify=False) as client: 
            
            res_base = client.get(target, headers=headers_baseline, timeout=5.0)
            res_anom = client.get(target, headers=headers_anomalous, timeout=5.0)
            
            print("\n================ [ FUZZING RESULTS ] ================")
            print(f"Baseline Probe  -> Status: {res_base.status_code} | Content Length: {len(res_base.text)}")
            print(f"Anomalous Probe -> Status: {res_anom.status_code} | Content Length: {len(res_anom.text)}")
            print("=====================================================")
            
            if res_base.status_code != res_anom.status_code:
                print("\n[!] CRITICAL ANOMALY DETECTED: Potential Parser Discrepancy!")
                print("[-] The WAF and Backend server handled the malformed header differently.")
            elif len(res_base.text) != len(res_anom.text):
                print("\n[!] CONTENT ANOMALY DETECTED: Status codes match, but response size differs.")
            else:
                print("\n[-] No discrepancy detected with this specific mutation.")
                
    except httpx.RequestError as exc:
        print(f"[!] Target Connection Error: {exc}")
